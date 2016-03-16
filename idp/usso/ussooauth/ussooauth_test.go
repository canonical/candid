// Copyright 2015 Canonical Ltd.

package ussooauth_test

import (
	"net/http"

	"github.com/garyburd/go-oauth/oauth"
	"github.com/juju/idmclient/params"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/mockusso"
	"github.com/CanonicalLtd/blues-identity/idp/usso/ussooauth"
)

type ussooauthSuite struct {
	mockusso.Suite
	idp idp.IdentityProvider
}

var _ = gc.Suite(&ussooauthSuite{})

func (s *ussooauthSuite) SetUpTest(c *gc.C) {
	s.Suite.SetUpTest(c)
	s.idp = ussooauth.IdentityProvider
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
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
	}
	t, err := s.idp.URL(tc, "1")
	c.Assert(err, gc.IsNil)
	c.Assert(t, gc.Equals, "https://idp.test/oauth?waitid=1")
}

func (s *ussooauthSuite) TestHandleSuccess(c *gc.C) {
	b, err := bakery.NewService(bakery.NewServiceParams{})
	c.Assert(err, gc.IsNil)
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Bakery_:   b,
	}
	err = tc.UpdateUser(&params.User{
		ExternalID: "https://login.ubuntu.com/+id/test",
		Username:   params.Username("test"),
		FullName:   "Test User",
		Email:      "test@example.com",
	})
	c.Assert(err, gc.IsNil)
	s.MockUSSO.AddUser(&mockusso.User{
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
	tc.Request, err = http.NewRequest("GET", "http://example.com/oauth?waitid=2", nil)
	c.Assert(err, gc.IsNil)
	err = oc.SetAuthorizationHeader(
		tc.Request.Header,
		&oauth.Credentials{
			Token:  "test-token",
			Secret: "secret2",
		},
		tc.Request.Method,
		tc.Request.URL,
		nil,
	)
	c.Assert(err, gc.IsNil)
	s.idp.Handle(tc)
	idptest.AssertLoginSuccess(c, tc, checkers.TimeBefore, &params.User{
		ExternalID: "https://login.ubuntu.com/+id/test",
		Username:   params.Username("test"),
		FullName:   "Test User",
		Email:      "test@example.com",
	})
	c.Assert(tc.Response().Body.String(), gc.Equals, "login successful as user test\n")
}

func (s *ussooauthSuite) TestHandleVerifyFail(c *gc.C) {
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
	}
	err := tc.UpdateUser(&params.User{
		ExternalID: "https://login.ubuntu.com/+id/test",
		Username:   params.Username("test"),
		FullName:   "Test User",
		Email:      "test@example.com",
	})
	c.Assert(err, gc.IsNil)
	s.MockUSSO.AddUser(&mockusso.User{
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
	tc.Request, err = http.NewRequest("GET", "http://example.com/oauth?waitid=2", nil)
	c.Assert(err, gc.IsNil)
	err = oc.SetAuthorizationHeader(
		tc.Request.Header,
		&oauth.Credentials{
			Token:  "test-token2",
			Secret: "secret2",
		},
		tc.Request.Method,
		tc.Request.URL,
		nil,
	)
	c.Assert(err, gc.IsNil)
	s.idp.Handle(tc)
	idptest.AssertLoginFailure(c, tc, `invalid OAuth credentials`)
}
