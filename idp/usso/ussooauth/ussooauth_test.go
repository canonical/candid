// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package ussooauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/gomodule/oauth1/oauth"
	"gopkg.in/yaml.v2"

	"github.com/canonical/candid/config"
	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/idptest"
	"github.com/canonical/candid/idp/usso/internal/mockusso"
	"github.com/canonical/candid/idp/usso/ussooauth"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/store"
)

func TestConfig(t *testing.T) {
	c := qt.New(t)

	configYaml := `
identity-providers:
 - type: usso_oauth
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(configYaml), &conf)
	c.Assert(err, qt.IsNil)
	c.Assert(conf.IdentityProviders, qt.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), qt.Equals, "usso_oauth")
}

func TestUSSOAuth(t *testing.T) {
	qtsuite.Run(qt.New(t), &ussooauthSuite{})
}

type ussooauthSuite struct {
	idptest *idptest.Fixture

	idp idp.IdentityProvider
}

func (s *ussooauthSuite) Init(c *qt.C) {
	s.idptest = idptest.NewFixture(c, candidtest.NewStore())
	s.idp = ussooauth.IdentityProvider
	err := s.idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, "https://idp.test"))
	c.Assert(err, qt.IsNil)
}

func (s *ussooauthSuite) TestName(c *qt.C) {
	c.Assert(s.idp.Name(), qt.Equals, "usso_oauth")
}

func (s *ussooauthSuite) TestDescription(c *qt.C) {
	c.Assert(s.idp.Description(), qt.Equals, "Ubuntu SSO OAuth")
}

func (s *ussooauthSuite) TestIconURL(c *qt.C) {
	c.Assert(s.idp.IconURL(), qt.Equals, "")
}

func (s *ussooauthSuite) TestInteractive(c *qt.C) {
	c.Assert(s.idp.Interactive(), qt.Equals, false)
}

func (s *ussooauthSuite) TestHidden(c *qt.C) {
	c.Assert(s.idp.Hidden(), qt.Equals, false)
}

func (s *ussooauthSuite) TestURL(c *qt.C) {
	t := s.idp.URL("1")
	c.Assert(t, qt.Equals, "https://idp.test/login?id=1")
}

func (s *ussooauthSuite) TestHandleSuccess(c *qt.C) {
	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()
	err := s.idptest.Store.Store.UpdateIdentity(
		s.idptest.Ctx,
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("usso", "https://login.ubuntu.com/+id/test"),
			Username:   "test",
			Name:       "Test User",
			Email:      "test@example.com",
		},
		store.Update{
			store.Username: store.Set,
			store.Name:     store.Set,
			store.Email:    store.Set,
		},
	)
	c.Assert(err, qt.IsNil)
	ussoSrv.MockUSSO.AddUser(&mockusso.User{
		ID:             "test",
		NickName:       "test",
		FullName:       "Test User",
		Email:          "test@example.com",
		ConsumerSecret: "secret1",
		TokenKey:       "test-token",
		TokenSecret:    "secret2",
	})
	oc := &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  "test",
			Secret: "secret1",
		},
		SignatureMethod: oauth.HMACSHA1,
	}
	req, err := http.NewRequest("GET", "http://example.com/oauth?id=2", nil)
	c.Assert(err, qt.IsNil)
	err = oc.SetAuthorizationHeader(
		req.Header,
		&oauth.Credentials{
			Token:  "test-token",
			Secret: "secret2",
		},
		req.Method,
		req.URL,
		nil,
	)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginSuccess(c, "test")
}

func (s *ussooauthSuite) TestHandleVerifyFail(c *qt.C) {
	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()
	err := s.idptest.Store.Store.UpdateIdentity(
		s.idptest.Ctx,
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("usso", "https://login.ubuntu.com/+id/test"),
			Username:   "test",
			Name:       "Test User",
			Email:      "test@example.com",
		},
		store.Update{
			store.Username: store.Set,
			store.Name:     store.Set,
			store.Email:    store.Set,
		},
	)
	c.Assert(err, qt.IsNil)
	ussoSrv.MockUSSO.AddUser(&mockusso.User{
		ID:             "test",
		NickName:       "test",
		FullName:       "Test User",
		Email:          "test@example.com",
		ConsumerSecret: "secret1",
		TokenKey:       "test-token",
		TokenSecret:    "secret2",
	})
	oc := &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  "test",
			Secret: "secret1",
		},
		SignatureMethod: oauth.HMACSHA1,
	}
	req, err := http.NewRequest("GET", "http://example.com/oauth?id=2", nil)
	c.Assert(err, qt.IsNil)
	err = oc.SetAuthorizationHeader(
		req.Header,
		&oauth.Credentials{
			Token:  "test-token2",
			Secret: "secret2",
		},
		req.Method,
		req.URL,
		nil,
	)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginFailureMatches(c, `invalid OAuth credentials`)
}
