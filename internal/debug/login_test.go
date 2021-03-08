// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package debug_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/juju/qthttptest"
	"golang.org/x/crypto/nacl/box"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v3/bakery"

	"gopkg.in/canonical/candid.v2/internal/candidtest"
	"gopkg.in/canonical/candid.v2/internal/debug"
)

func TestLogin(t *testing.T) {
	qtsuite.Run(qt.New(t), &loginSuite{})
}

type loginSuite struct {
	srv *candidtest.Server
}

func (s *loginSuite) Init(c *qt.C) {
	s.srv = newFixture(c).srv
}

func (s *loginSuite) TestCookieEncodeDecode(c *qt.C) {
	c1 := &debug.Cookie{
		ExpireTime: time.Now(),
		ID:         "https://example.com/ID",
		Teams:      []string{"t1", "t2"},
	}
	v, err := debug.EncodeCookie(s.srv.Key, c1)
	c.Assert(err, qt.IsNil)
	c2, err := debug.DecodeCookie(s.srv.Key, v)
	c.Assert(err, qt.IsNil)
	c.Assert(c1.ExpireTime.Equal(c1.ExpireTime), qt.Equals, true, qt.Commentf("expire times not equal expecting: %s, obtained: %s", c1.ExpireTime, c2.ExpireTime))
	c1.ExpireTime = time.Time{}
	c2.ExpireTime = time.Time{}
	c.Assert(c2, qt.DeepEquals, c1)
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

func (s *loginSuite) TestCheckLogin(c *qt.C) {
	for i, test := range testCheckLogin {
		c.Logf("%d. %s", i, test.about)
		var cookies []*http.Cookie
		if test.cookieValue != nil {
			value, err := test.cookieValue(s.srv.Key)
			c.Assert(err, qt.IsNil)
			cookies = append(cookies, &http.Cookie{
				Name:  "debug-login",
				Value: value,
			})
		}
		resp := qthttptest.Do(c, qthttptest.DoRequestParams{
			URL:     s.srv.URL + "/debug/pprof/",
			Do:      doNoRedirect,
			Cookies: cookies,
		})
		defer resp.Body.Close()
		if !test.expectLoginRequest {
			c.Assert(resp.StatusCode, qt.Equals, http.StatusOK)
			continue
		}
		c.Assert(resp.StatusCode, qt.Equals, http.StatusFound)
		c.Assert(resp.Header.Get("Location"), qt.Not(qt.Equals), "")
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
