// Copyright 2015 Canonical Ltd.

package v1_test

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/juju/idmclient/params"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/test"
	"github.com/CanonicalLtd/blues-identity/store"
)

type loginSuite struct {
	apiSuite
}

var _ = gc.Suite(&loginSuite{})

func (s *loginSuite) SetUpTest(c *gc.C) {
	s.Params.IdentityProviders = []idp.IdentityProvider{
		test.NewIdentityProvider(test.Params{
			Name: "test",
		}),
		test.NewIdentityProvider(test.Params{
			Name:   "test2",
			Domain: "test2",
		}),
	}
	s.apiSuite.SetUpTest(c)
}

func (s *loginSuite) TestInteractiveLogin(c *gc.C) {
	jar := &testCookieJar{}
	client := httpbakery.NewClient()
	visitor := test.Visitor{
		User: &params.User{
			Username:   "test",
			ExternalID: "test:test",
			FullName:   "Test User",
			Email:      "test@example.com",
			IDPGroups:  []string{"test1", "test2"},
		},
	}
	u, err := url.Parse(s.URL + "/v1/idp/test/login")
	c.Assert(err, gc.Equals, nil)
	err = visitor.VisitWebPage(testContext, client, map[string]*url.URL{httpbakery.UserInteractionMethod: u})
	c.Assert(err, gc.Equals, nil)
	c.Assert(jar.cookies, gc.HasLen, 0)
	id := store.Identity{
		ProviderID: "test:test",
	}
	err = s.Params.Store.Identity(testContext, &id)
	c.Assert(err, gc.Equals, nil)
	c.Assert(id.LastLogin.After(time.Now().Add(-1*time.Second)), gc.Equals, true)
}

func (s *loginSuite) TestNonInteractiveLogin(c *gc.C) {
	jar := &testCookieJar{}
	client := httpbakery.NewClient()
	visitor := test.Visitor{
		User: &params.User{
			Username:   "test",
			ExternalID: "test:test",
			FullName:   "Test User",
			Email:      "test@example.com",
			IDPGroups:  []string{"test1", "test2"},
		},
	}
	u, err := url.Parse(s.URL + "/v1/idp/test/login")
	c.Assert(err, gc.Equals, nil)
	err = visitor.VisitWebPage(testContext, client, map[string]*url.URL{"test": u})
	c.Assert(err, gc.Equals, nil)
	c.Assert(jar.cookies, gc.HasLen, 0)
	id := store.Identity{
		ProviderID: "test:test",
	}
	err = s.Params.Store.Identity(testContext, &id)
	c.Assert(err, gc.Equals, nil)
	c.Assert(id.LastLogin.After(time.Now().Add(-1*time.Second)), gc.Equals, true)
}

func (s *loginSuite) TestLoginFailure(c *gc.C) {
	jar := &testCookieJar{}
	client := httpbakery.NewClient()
	visitor := test.Visitor{
		User: &params.User{},
	}
	u, err := url.Parse(s.URL + "/v1/idp/test/login")
	c.Assert(err, gc.Equals, nil)
	err = visitor.VisitWebPage(testContext, client, map[string]*url.URL{httpbakery.UserInteractionMethod: u})
	c.Assert(err, gc.ErrorMatches, `Post .*/v1/idp/test/test-login: identity not specified`)
	c.Assert(jar.cookies, gc.HasLen, 0)
}

func (s *loginSuite) TestInteractiveIdentityProviderSelection(c *gc.C) {
	resp := s.getNoRedirect(c, "/v1/login")
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusFound)
	c.Assert(resp.Header.Get("Location"), gc.Equals, s.URL+"/v1/idp/test/test-login")
}

func (s *loginSuite) TestInteractiveIdentityProviderSelectionWithDomain(c *gc.C) {
	resp := s.getNoRedirect(c, "/v1/login?domain=test2")
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusFound)
	c.Assert(resp.Header.Get("Location"), gc.Equals, s.URL+"/v1/idp/test2/test-login")
}

func (s *loginSuite) TestLoginMethodsIncludesAgent(c *gc.C) {
	req, err := http.NewRequest("GET", "/v1/login", nil)
	c.Assert(err, gc.Equals, nil)
	req.Header.Set("Accept", "application/json")
	resp := s.Do(c, req)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	buf, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, gc.Equals, nil)
	var lm params.LoginMethods
	err = json.Unmarshal(buf, &lm)
	c.Assert(err, gc.Equals, nil)
	c.Assert(lm.Agent, gc.Equals, s.URL+"/v1/agent-login")
}

func (s *loginSuite) getNoRedirect(c *gc.C, path string) *http.Response {
	req, err := http.NewRequest("GET", path, nil)
	c.Assert(err, gc.Equals, nil)
	return s.RoundTrip(c, req)
}
