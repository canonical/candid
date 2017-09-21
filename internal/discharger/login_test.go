// Copyright 2015 Canonical Ltd.

package discharger_test

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
	visitor := test.Interactor{
		User: &params.User{
			Username:   "test",
			ExternalID: "test:test",
			FullName:   "Test User",
			Email:      "test@example.com",
			IDPGroups:  []string{"test1", "test2"},
		},
	}
	u, err := url.Parse(s.URL + "/login/test/login")
	c.Assert(err, gc.Equals, nil)
	err = visitor.LegacyInteract(testContext, client, "", u)
	c.Assert(err, gc.Equals, nil)
	c.Assert(jar.cookies, gc.HasLen, 0)
	id := store.Identity{
		ProviderID: "test:test",
	}
	err = s.Params.Store.Identity(testContext, &id)
	c.Assert(err, gc.Equals, nil)
	c.Assert(id.LastLogin.After(time.Now().Add(-1*time.Second)), gc.Equals, true, gc.Commentf("%#v", id))
}

func (s *loginSuite) TestNonInteractiveLogin(c *gc.C) {
	jar := &testCookieJar{}
	client := httpbakery.NewClient()
	visitor := test.Interactor{
		User: &params.User{
			Username:   "test",
			ExternalID: "test:test",
			FullName:   "Test User",
			Email:      "test@example.com",
			IDPGroups:  []string{"test1", "test2"},
		},
	}
	req, err := http.NewRequest("GET", "/", nil)
	c.Assert(err, gc.Equals, nil)
	ierr := httpbakery.NewInteractionRequiredError(nil, req)
	ierr.SetInteraction("test", map[string]string{"url": s.URL + "/login/test/interact"})
	_, err = visitor.Interact(testContext, client, "", ierr)
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
	visitor := test.Interactor{
		User: &params.User{},
	}
	u, err := url.Parse(s.URL + "/login/test/login")
	c.Assert(err, gc.Equals, nil)
	err = visitor.LegacyInteract(testContext, client, "", u)
	c.Assert(err, gc.ErrorMatches, `Post .*/login/test/login: identity not specified`)
	c.Assert(jar.cookies, gc.HasLen, 0)
}

func (s *loginSuite) TestInteractiveIdentityProviderSelection(c *gc.C) {
	resp := s.getNoRedirect(c, "/login")
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusFound)
	c.Assert(resp.Header.Get("Location"), gc.Equals, s.URL+"/login/test/login")
}

func (s *loginSuite) TestInteractiveIdentityProviderSelectionWithDomain(c *gc.C) {
	resp := s.getNoRedirect(c, "/login?domain=test2")
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusFound)
	c.Assert(resp.Header.Get("Location"), gc.Equals, s.URL+"/login/test2/login")
}

func (s *loginSuite) TestLoginMethodsIncludesAgent(c *gc.C) {
	req, err := http.NewRequest("GET", "/login", nil)
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
	c.Assert(lm.Agent, gc.Equals, s.URL+"/login/agent")
}

func (s *loginSuite) getNoRedirect(c *gc.C, path string) *http.Response {
	req, err := http.NewRequest("GET", path, nil)
	c.Assert(err, gc.Equals, nil)
	return s.RoundTrip(c, req)
}
