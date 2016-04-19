// Copyright 2016 Canonical Ltd.

package debug_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	"golang.org/x/crypto/nacl/box"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"

	"github.com/CanonicalLtd/blues-identity/internal/debug"
)

type loginSuite struct {
	apiSuite
}

var _ = gc.Suite(&loginSuite{})

func (s *loginSuite) SetUpSuite(c *gc.C) {
	s.apiSuite.SetUpSuite(c)
	s.teams = []string{"debuggers"}
}

func (s *loginSuite) TestCookieEncodeDecode(c *gc.C) {
	c1 := &debug.Cookie{
		ExpireTime: time.Now(),
		ID:         "https://example.com/ID",
		Teams:      []string{"t1", "t2"},
	}
	v, err := debug.EncodeCookie(s.keyPair, c1)
	c.Assert(err, jc.ErrorIsNil)
	c2, err := debug.DecodeCookie(s.keyPair, v)
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
			value, err := test.cookieValue(s.keyPair)
			c.Assert(err, gc.IsNil)
			cookies = append(cookies, &http.Cookie{
				Name:  "debug-login",
				Value: value,
			})
		}
		resp := httptesting.Do(c, httptesting.DoRequestParams{
			Handler: s.srv,
			URL:     "/debug/pprof/",
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
