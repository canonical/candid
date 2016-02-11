// Copyright 2015 Canonical Ltd.

package v1_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/juju/httprequest"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/test"
	"github.com/CanonicalLtd/blues-identity/params"
)

type loginSuite struct {
	apiSuite
	netSrv *httptest.Server
}

var _ = gc.Suite(&loginSuite{})

func (s *loginSuite) SetUpSuite(c *gc.C) {
	s.apiSuite.idps = []idp.IdentityProvider{
		test.IdentityProvider,
	}
	s.apiSuite.SetUpSuite(c)
}

func (s *loginSuite) SetUpTest(c *gc.C) {
	s.apiSuite.SetUpTest(c)
	s.netSrv = httptest.NewServer(s.srv)
}

func (s *loginSuite) TearDownTest(c *gc.C) {
	s.netSrv.Close()
	s.apiSuite.TearDownTest(c)
}

func (s *loginSuite) TestInteractiveLogin(c *gc.C) {
	jar := &testCookieJar{}
	client := &http.Client{
		Jar: jar,
	}
	visitor := test.WebPageVisitor{
		Client: &httprequest.Client{Doer: client},
		User: &params.User{
			Username:   "test",
			ExternalID: "http://example.com/+id/test",
			FullName:   "Test User",
			Email:      "test@example.com",
			IDPGroups:  []string{"test1", "test2"},
		},
	}
	u, err := url.Parse(location + "/v1/login")
	c.Assert(err, gc.IsNil)
	err = visitor.Interactive(u)
	c.Assert(err, gc.IsNil)
	s.assertMacaroon(c, jar, "test")
}

func (s *loginSuite) TestNonInteractiveLogin(c *gc.C) {
	jar := &testCookieJar{}
	client := &http.Client{
		Jar: jar,
	}
	visitor := test.WebPageVisitor{
		Client: &httprequest.Client{Doer: client},
		User: &params.User{
			Username:   "test",
			ExternalID: "http://example.com/+id/test",
			FullName:   "Test User",
			Email:      "test@example.com",
			IDPGroups:  []string{"test1", "test2"},
		},
	}
	u, err := url.Parse(location + "/v1/login")
	c.Assert(err, gc.IsNil)
	err = visitor.NonInteractive(u)
	c.Assert(err, gc.IsNil)
	s.assertMacaroon(c, jar, "test")
}

func (s *loginSuite) TestLoginFailure(c *gc.C) {
	jar := &testCookieJar{}
	client := &http.Client{
		Jar: jar,
	}
	visitor := test.WebPageVisitor{
		Client: &httprequest.Client{Doer: client},
		User:   &params.User{},
	}
	u, err := url.Parse(location + "/v1/login")
	c.Assert(err, gc.IsNil)
	err = visitor.Interactive(u)
	c.Assert(err, gc.ErrorMatches, `POST .*: httprequest: user "" not found: not found`)
	c.Assert(jar.cookies, gc.HasLen, 0)
}

func (s *loginSuite) TestLogout(c *gc.C) {
	jar, err := cookiejar.New(&cookiejar.Options{})
	c.Assert(err, gc.IsNil)
	client := &http.Client{
		Jar: jar,
	}
	visitor := test.WebPageVisitor{
		Client: &httprequest.Client{Doer: client},
		User: &params.User{
			Username:   "test",
			ExternalID: "http://example.com/+id/test",
			FullName:   "Test User",
			Email:      "test@example.com",
			IDPGroups:  []string{"test1", "test2"},
		},
	}
	u, err := url.Parse(location + "/v1/login")
	c.Assert(err, gc.IsNil)
	err = visitor.Interactive(u)
	c.Assert(err, gc.IsNil)
	u, err = url.Parse(location)
	cookies := jar.Cookies(u)
	c.Assert(cookies, gc.HasLen, 1)
	jar.SetCookies(u, []*http.Cookie{{
		Name:   "test",
		Value:  "test",
		Path:   "/",
		MaxAge: 100 * 24 * 60 * 60,
	}})
	cookies = jar.Cookies(u)
	c.Assert(cookies, gc.HasLen, 2)
	resp, err := client.Get(location + "/v1/logout")
	c.Assert(err, gc.IsNil)
	cookies = resp.Cookies()
	c.Assert(cookies, gc.HasLen, 1)
	cookies = jar.Cookies(u)
	c.Assert(cookies, gc.HasLen, 1)
	c.Assert(cookies[0].Name, gc.Equals, "test")
}

func (s *loginSuite) assertMacaroon(c *gc.C, jar *testCookieJar, userId string) {
	var ms macaroon.Slice
	for _, cookie := range jar.cookies {
		if strings.HasPrefix(cookie.Name, "macaroon-") {
			data, err := base64.StdEncoding.DecodeString(cookie.Value)
			c.Assert(err, gc.IsNil)
			err = json.Unmarshal(data, &ms)
			c.Assert(err, gc.IsNil)
			break
		}
	}
	c.Assert(ms, gc.Not(gc.HasLen), 0)
	cavs := ms[0].Caveats()
	var found bool
	for _, cav := range cavs {
		if strings.HasPrefix(cav.Id, "declared username") {
			found = true
			un := strings.TrimPrefix(cav.Id, "declared username ")
			c.Assert(un, gc.Equals, userId)
		}
	}
	c.Assert(found, gc.Equals, true, gc.Commentf("no username  caveat"))
}
