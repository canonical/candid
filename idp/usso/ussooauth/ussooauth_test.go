// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package ussooauth_test

import (
	"net/http"
	"net/http/httptest"

	"github.com/garyburd/go-oauth/oauth"
	gc "gopkg.in/check.v1"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/mockusso"
	"github.com/CanonicalLtd/blues-identity/idp/usso/ussooauth"
	"github.com/CanonicalLtd/blues-identity/store"
)

type ussooauthSuite struct {
	idptest.Suite
	mockUSSOSuite mockusso.Suite

	idp idp.IdentityProvider
}

var _ = gc.Suite(&ussooauthSuite{})

func (s *ussooauthSuite) SetUpSuite(c *gc.C) {
	s.Suite.SetUpSuite(c)
	s.mockUSSOSuite.SetUpSuite(c)
}

func (s *ussooauthSuite) TearDownSuite(c *gc.C) {
	s.mockUSSOSuite.TearDownSuite(c)
	s.Suite.TearDownSuite(c)
}

func (s *ussooauthSuite) SetUpTest(c *gc.C) {
	s.Suite.SetUpTest(c)
	s.mockUSSOSuite.SetUpTest(c)
	s.idp = ussooauth.IdentityProvider
	err := s.idp.Init(s.Ctx, s.InitParams(c, "https://idp.test"))
	c.Assert(err, gc.Equals, nil)
}

func (s *ussooauthSuite) TearDownTest(c *gc.C) {
	s.mockUSSOSuite.TearDownTest(c)
	s.Suite.TearDownTest(c)
}

func (s *ussooauthSuite) TestConfig(c *gc.C) {
	configYaml := `
identity-providers:
 - type: usso_oauth
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(configYaml), &conf)
	c.Assert(err, gc.IsNil)
	c.Assert(conf.IdentityProviders, gc.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), gc.Equals, "usso_oauth")
}

func (s *ussooauthSuite) TestName(c *gc.C) {
	c.Assert(s.idp.Name(), gc.Equals, "usso_oauth")
}

func (s *ussooauthSuite) TestDescription(c *gc.C) {
	c.Assert(s.idp.Description(), gc.Equals, "Ubuntu SSO OAuth")
}

func (s *ussooauthSuite) TestInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, false)
}

func (s *ussooauthSuite) TestURL(c *gc.C) {
	t := s.idp.URL("1")
	c.Assert(t, gc.Equals, "https://idp.test/login?id=1")
}

func (s *ussooauthSuite) TestHandleSuccess(c *gc.C) {
	err := s.Store.UpdateIdentity(
		s.Ctx,
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
	c.Assert(err, gc.Equals, nil)
	s.mockUSSOSuite.MockUSSO.AddUser(&mockusso.User{
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
	c.Assert(err, gc.Equals, nil)
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
	c.Assert(err, gc.Equals, nil)
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginSuccess(c, "test")
}

func (s *ussooauthSuite) TestHandleVerifyFail(c *gc.C) {
	err := s.Store.UpdateIdentity(
		s.Ctx,
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
	c.Assert(err, gc.Equals, nil)
	s.mockUSSOSuite.MockUSSO.AddUser(&mockusso.User{
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
	c.Assert(err, gc.Equals, nil)
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
	c.Assert(err, gc.IsNil)
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginFailureMatches(c, `invalid OAuth credentials`)
}
