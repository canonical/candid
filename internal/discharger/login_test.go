// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger_test

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/test"
	"github.com/CanonicalLtd/candid/internal/candidtest"
	"github.com/CanonicalLtd/candid/internal/discharger"
	"github.com/CanonicalLtd/candid/internal/identity"
	"github.com/CanonicalLtd/candid/store"
)

func TestLogin(t *testing.T) {
	qtsuite.Run(qt.New(t), &loginSuite{})
}

type loginSuite struct {
	store *candidtest.Store
	srv   *candidtest.Server
}

func (s *loginSuite) Init(c *qt.C) {
	s.store = candidtest.NewStore()
	sp := s.store.ServerParams()
	sp.IdentityProviders = []idp.IdentityProvider{
		test.NewIdentityProvider(test.Params{
			Name: "test",
		}),
		test.NewIdentityProvider(test.Params{
			Name:   "test2",
			Domain: "test2",
		}),
	}
	s.srv = candidtest.NewServer(c, sp, map[string]identity.NewAPIHandlerFunc{
		"discharger": discharger.NewAPIHandler,
	})
}

func (s *loginSuite) TestLegacyInteractiveLogin(c *qt.C) {
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
	u, err := url.Parse(s.srv.URL + "/login/test/login")
	c.Assert(err, qt.Equals, nil)
	err = visitor.LegacyInteract(testContext, client, "", u)
	c.Assert(err, qt.Equals, nil)
	c.Assert(jar.cookies, qt.HasLen, 0)
	id := store.Identity{
		ProviderID: "test:test",
	}
	err = s.store.Store.Identity(testContext, &id)
	c.Assert(err, qt.Equals, nil)
	c.Assert(id.LastLogin.After(time.Now().Add(-1*time.Second)), qt.Equals, true, qt.Commentf("%#v", id))
}

func (s *loginSuite) TestNonInteractiveLogin(c *qt.C) {
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
	c.Assert(err, qt.Equals, nil)
	ierr := httpbakery.NewInteractionRequiredError(nil, req)
	ierr.SetInteraction("test", map[string]string{"url": s.srv.URL + "/login/test/interact"})
	_, err = visitor.Interact(testContext, client, "", ierr)
	c.Assert(err, qt.Equals, nil)
	c.Assert(jar.cookies, qt.HasLen, 0)
	id := store.Identity{
		ProviderID: "test:test",
	}
	err = s.store.Store.Identity(testContext, &id)
	c.Assert(err, qt.Equals, nil)
	c.Assert(id.LastLogin.After(time.Now().Add(-1*time.Second)), qt.Equals, true)
}

func (s *loginSuite) TestLegacyLoginFailure(c *qt.C) {
	jar := &testCookieJar{}
	client := httpbakery.NewClient()
	visitor := test.Interactor{
		User: &params.User{},
	}
	u, err := url.Parse(s.srv.URL + "/login/test/login")
	c.Assert(err, qt.Equals, nil)
	err = visitor.LegacyInteract(testContext, client, "", u)
	c.Assert(err, qt.ErrorMatches, `Post .*/login/test/login: identity not specified`)
	c.Assert(jar.cookies, qt.HasLen, 0)
}

func (s *loginSuite) TestInteractiveIdentityProviderSelection(c *qt.C) {
	resp := s.getNoRedirect(c, "/login")
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, qt.Equals, http.StatusFound)
	c.Assert(resp.Header.Get("Location"), qt.Equals, s.srv.URL+"/login/test/login")
}

func (s *loginSuite) TestInteractiveIdentityProviderSelectionWithDomain(c *qt.C) {
	resp := s.getNoRedirect(c, "/login?domain=test2")
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, qt.Equals, http.StatusFound)
	c.Assert(resp.Header.Get("Location"), qt.Equals, s.srv.URL+"/login/test2/login")
}

func (s *loginSuite) TestLoginMethodsIncludesAgent(c *qt.C) {
	req, err := http.NewRequest("GET", "/login-legacy", nil)
	c.Assert(err, qt.Equals, nil)
	req.Header.Set("Accept", "application/json")
	resp := s.srv.Do(c, req)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, qt.Equals, http.StatusOK)
	buf, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, qt.Equals, nil)
	var lm params.LoginMethods
	err = json.Unmarshal(buf, &lm)
	c.Assert(err, qt.Equals, nil)
	c.Assert(lm.Agent, qt.Equals, s.srv.URL+"/login/legacy-agent")
}

func (s *loginSuite) getNoRedirect(c *qt.C, path string) *http.Response {
	req, err := http.NewRequest("GET", path, nil)
	c.Assert(err, qt.Equals, nil)
	return s.srv.RoundTrip(c, req)
}
