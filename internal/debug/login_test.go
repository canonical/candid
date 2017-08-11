// Copyright 2016 Canonical Ltd.

package debug_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	"golang.org/x/crypto/nacl/box"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/mgorootkeystore"

	"github.com/CanonicalLtd/blues-identity/internal/debug"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
	"github.com/CanonicalLtd/blues-identity/mgostore"
)

type loginSuite struct {
	testing.IsolatedMgoSuite
	idmtest.ServerSuite

	db *mgostore.Database
}

var _ = gc.Suite(&loginSuite{})

func (s *loginSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.db, err = mgostore.NewDatabase(s.Session.DB("idm-test"))
	c.Assert(err, gc.Equals, nil)

	s.Params.MeetingStore = s.db.MeetingStore()
	s.Params.RootKeyStore = s.db.BakeryRootKeyStore(mgorootkeystore.Policy{ExpiryDuration: time.Minute})
	s.Params.Store = s.db.Store()
	s.Params.DebugStatusCheckerFuncs = s.db.DebugStatusCheckerFuncs()
	s.Params.Key, err = bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
	s.Params.DebugTeams = []string{"debuggers"}

	s.Versions = map[string]identity.NewAPIHandlerFunc{
		version: debug.NewAPIHandler,
	}
	s.ServerSuite.SetUpTest(c)
}

func (s *loginSuite) TearDownTest(c *gc.C) {
	s.ServerSuite.TearDownTest(c)
	s.db.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}
func (s *loginSuite) TestCookieEncodeDecode(c *gc.C) {
	c1 := &debug.Cookie{
		ExpireTime: time.Now(),
		ID:         "https://example.com/ID",
		Teams:      []string{"t1", "t2"},
	}
	v, err := debug.EncodeCookie(s.Params.Key, c1)
	c.Assert(err, jc.ErrorIsNil)
	c2, err := debug.DecodeCookie(s.Params.Key, v)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(c1.ExpireTime.Equal(c1.ExpireTime), gc.Equals, true, gc.Commentf("expire times not equal expecting: %s, obtained: %s", c1.ExpireTime, c2.ExpireTime))
	c1.ExpireTime = time.Time{}
	c2.ExpireTime = time.Time{}
	c.Assert(c2, jc.DeepEquals, c1)
}

var testCheckLogin = []struct {
	about              string
	cookieValue        func(key *bakery.KeyPair) (string, error)
	expectLoginRequest bool
}{{
	about: "good cookie",
	cookieValue: cookieEncode(debug.Cookie{
		ExpireTime: time.Now().Add(1 * time.Hour),
		Teams:      []string{"debuggers"},
	}),
}, {
	about:              "no cookie",
	expectLoginRequest: true,
}, {
	about: "too old",
	cookieValue: cookieEncode(debug.Cookie{
		ExpireTime: time.Now().Add(-1 * time.Minute),
		Teams:      []string{"debuggers"},
	}),
	expectLoginRequest: true,
}, {
	about: "wrong teams",
	cookieValue: cookieEncode(debug.Cookie{
		ExpireTime: time.Now().Add(1 * time.Hour),
		Teams:      []string{"not-debuggers"},
	}),
	expectLoginRequest: true,
}, {
	about: "bad base64",
	cookieValue: func(*bakery.KeyPair) (string, error) {
		return "A", nil
	},
	expectLoginRequest: true,
}, {
	about: "wrong key",
	cookieValue: func(*bakery.KeyPair) (string, error) {
		k2, err := bakery.GenerateKey()
		if err != nil {
			return "", err
		}
		return cookieEncode(debug.Cookie{
			ExpireTime: time.Now().Add(1 * time.Hour),
			Teams:      []string{"debuggers"},
		})(k2)
	},
	expectLoginRequest: true,
}, {
	about: "wrong signing key",
	cookieValue: func(key *bakery.KeyPair) (string, error) {
		k2, err := bakery.GenerateKey()
		if err != nil {
			return "", err
		}
		k3 := &bakery.KeyPair{
			Public:  key.Public,
			Private: k2.Private,
		}
		return cookieEncode(debug.Cookie{
			ExpireTime: time.Now().Add(1 * time.Hour),
			Teams:      []string{"debuggers"},
		})(k3)
	},
	expectLoginRequest: true,
}, {
	about: "bad json",
	cookieValue: func(key *bakery.KeyPair) (string, error) {
		data := []byte("{")
		var nonce [24]byte
		_, err := rand.Read(nonce[:])
		if err != nil {
			return "", err
		}
		edata := nonce[:]
		edata = box.Seal(edata, data, &nonce, (*[bakery.KeyLen]byte)(&key.Public.Key), (*[bakery.KeyLen]byte)(&key.Private.Key))
		return base64.StdEncoding.EncodeToString(edata), nil
	},
	expectLoginRequest: true,
}}

func (s *loginSuite) TestCheckLogin(c *gc.C) {
	for i, test := range testCheckLogin {
		c.Logf("%d. %s", i, test.about)
		var cookies []*http.Cookie
		if test.cookieValue != nil {
			value, err := test.cookieValue(s.Params.Key)
			c.Assert(err, gc.IsNil)
			cookies = append(cookies, &http.Cookie{
				Name:  "debug-login",
				Value: value,
			})
		}
		resp := httptesting.Do(c, httptesting.DoRequestParams{
			URL:     s.URL + "/debug/pprof/",
			Do:      doNoRedirect,
			Cookies: cookies,
		})
		defer resp.Body.Close()
		if !test.expectLoginRequest {
			c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
			continue
		}
		c.Assert(resp.StatusCode, gc.Equals, http.StatusFound)
		c.Assert(resp.Header.Get("Location"), gc.Not(gc.Equals), "")
	}
}

func cookieEncode(v interface{}) func(*bakery.KeyPair) (string, error) {
	return func(key *bakery.KeyPair) (string, error) {
		data, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		var nonce [24]byte
		_, err = rand.Read(nonce[:])
		if err != nil {
			return "", err
		}
		edata := nonce[:]
		edata = box.Seal(edata, data, &nonce, (*[bakery.KeyLen]byte)(&key.Public.Key), (*[bakery.KeyLen]byte)(&key.Private.Key))
		return base64.StdEncoding.EncodeToString(edata), nil
	}
}

func doNoRedirect(req *http.Request) (*http.Response, error) {
	resp, err := noRedirectClient.Do(req)
	if err == nil {
		return resp, nil
	}
	if uerr, ok := err.(*url.Error); ok {
		err := uerr.Err
		if errgo.Cause(err) == errStopRedirect {
			return resp, nil
		}
	}
	return resp, err
}

var errStopRedirect = errgo.New("no redirects")

var noRedirectClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errStopRedirect
	},
}
