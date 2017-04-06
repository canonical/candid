// Copyright 2015 Canonical Ltd.

package v1_test

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/juju/idmclient/params"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/test"
)

type loginSuite struct {
	apiSuite
	netSrv *httptest.Server
}

var _ = gc.Suite(&loginSuite{})

func (s *loginSuite) SetUpSuite(c *gc.C) {
	s.apiSuite.idps = []idp.IdentityProvider{
		test.NewIdentityProvider(test.Params{
			Name: "test",
		}),
		test.NewIdentityProvider(test.Params{
			Name:   "test2",
			Domain: "test2",
		}),
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

func (s *loginSuite) TearDownSuite(c *gc.C) {
	s.apiSuite.TearDownSuite(c)
}

func (s *loginSuite) TestInteractiveLogin(c *gc.C) {
	jar := &testCookieJar{}
	client := httpbakery.NewClient()
	visitor := test.Visitor{
		User: &params.User{
			Username:   "test",
			ExternalID: "http://example.com/+id/test",
			FullName:   "Test User",
			Email:      "test@example.com",
			IDPGroups:  []string{"test1", "test2"},
		},
	}
	u, err := url.Parse(location + "/v1/idp/test/login")
	c.Assert(err, gc.IsNil)
	err = visitor.VisitWebPage(testContext, client, map[string]*url.URL{httpbakery.UserInteractionMethod: u})
	c.Assert(err, gc.IsNil)
	c.Assert(jar.cookies, gc.HasLen, 0)
	st := s.pool.GetNoLimit()
	defer st.Close()
	id, err := st.GetIdentity("test")
	c.Assert(err, gc.IsNil)
	c.Assert(id.LastLogin.After(time.Now().Add(-1*time.Second)), gc.Equals, true)
}

func (s *loginSuite) TestNonInteractiveLogin(c *gc.C) {
	jar := &testCookieJar{}
	client := httpbakery.NewClient()
	visitor := test.Visitor{
		User: &params.User{
			Username:   "test",
			ExternalID: "http://example.com/+id/test",
			FullName:   "Test User",
			Email:      "test@example.com",
			IDPGroups:  []string{"test1", "test2"},
		},
	}
	u, err := url.Parse(location + "/v1/idp/test/login")
	c.Assert(err, gc.IsNil)
	err = visitor.VisitWebPage(testContext, client, map[string]*url.URL{"test": u})
	c.Assert(err, gc.IsNil)
	c.Assert(jar.cookies, gc.HasLen, 0)
	st := s.pool.GetNoLimit()
	defer st.Close()
	id, err := st.GetIdentity("test")
	c.Assert(err, gc.IsNil)
	c.Assert(id.LastLogin.After(time.Now().Add(-1*time.Second)), gc.Equals, true)
}

func (s *loginSuite) TestLoginFailure(c *gc.C) {
	jar := &testCookieJar{}
	client := httpbakery.NewClient()
	visitor := test.Visitor{
		User: &params.User{},
	}
	u, err := url.Parse(location + "/v1/idp/test/login")
	c.Assert(err, gc.IsNil)
	err = visitor.VisitWebPage(testContext, client, map[string]*url.URL{httpbakery.UserInteractionMethod: u})
	c.Assert(err, gc.ErrorMatches, `Post https:.*: user "" not found: not found`)
	c.Assert(jar.cookies, gc.HasLen, 0)
}

func (s *loginSuite) TestInteractiveIdentityProviderSelection(c *gc.C) {
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/v1/login", nil)
	c.Assert(err, gc.Equals, nil)
	s.srv.ServeHTTP(rr, req)
	c.Assert(rr.Code, gc.Equals, http.StatusFound)
	c.Assert(rr.HeaderMap.Get("Location"), gc.Equals, location+"/v1/idp/test/test-login")
}

func (s *loginSuite) TestInteractiveIdentityProviderSelectionWithDomain(c *gc.C) {
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/v1/login?domain=test2", nil)
	c.Assert(err, gc.Equals, nil)
	s.srv.ServeHTTP(rr, req)
	c.Assert(rr.Code, gc.Equals, http.StatusFound)
	c.Assert(rr.HeaderMap.Get("Location"), gc.Equals, location+"/v1/idp/test2/test-login")
}

func (s *loginSuite) TestLoginMethodsIncludesAgent(c *gc.C) {
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/v1/login", nil)
	c.Assert(err, gc.Equals, nil)
	req.Header.Set("Accept", "application/json")
	s.srv.ServeHTTP(rr, req)
	c.Assert(rr.Code, gc.Equals, http.StatusOK)
	buf, err := ioutil.ReadAll(rr.Body)
	c.Assert(err, gc.Equals, nil)
	var lm params.LoginMethods
	err = json.Unmarshal(buf, &lm)
	c.Assert(err, gc.Equals, nil)
	c.Assert(lm.Agent, gc.Equals, location+"/v1/agent-login")
}
