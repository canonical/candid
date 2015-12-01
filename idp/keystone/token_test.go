// Copyright 2015 Canonical Ltd.

package keystone_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	keystoneidp "github.com/CanonicalLtd/blues-identity/idp/keystone"
	"github.com/CanonicalLtd/blues-identity/idp/keystone/internal/mockkeystone"
	"github.com/CanonicalLtd/blues-identity/params"
)

type tokenSuite struct {
	server *mockkeystone.Server
	params keystoneidp.Params
	idp    idp.IdentityProvider
}

var _ = gc.Suite(&tokenSuite{})

func (s *tokenSuite) SetUpSuite(c *gc.C) {
	s.server = mockkeystone.NewServer()
	s.params = keystoneidp.Params{
		Name:        "openstack",
		Description: "OpenStack",
		Domain:      "openstack",
		URL:         s.server.URL,
	}
	s.server.TokensFunc = testTokens
	s.server.TenantsFunc = testTenants
}

func (s *tokenSuite) TearDownSuite(c *gc.C) {
	s.server.Close()
}

func (s *tokenSuite) SetUpTest(c *gc.C) {
	s.idp = keystoneidp.NewTokenIdentityProvider(s.params)
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, false)
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderHandle(c *gc.C) {
	var tok keystoneidp.Token
	tok.Login.ID = "789"
	body, err := json.Marshal(tok)
	c.Assert(err, gc.IsNil)
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1", bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	b, err := bakery.NewService(bakery.NewServiceParams{})
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Bakery_:   b,
		Request:   req,
	}
	s.idp.Handle(tc)
	idptest.AssertLoginSuccess(c, tc,
		checkers.New(
			checkers.TimeBefore,
		),
		&params.User{
			Username:   params.Username("testuser@openstack"),
			ExternalID: "abc@openstack",
			IDPGroups:  []string{"abc_project@openstack"},
		},
	)
	c.Assert(tc.Response().Body.String(), gc.Equals, "login successful as user testuser@openstack\n")
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderHandleBadToken(c *gc.C) {
	var tok keystoneidp.Token
	tok.Login.ID = "012"
	body, err := json.Marshal(tok)
	c.Assert(err, gc.IsNil)
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1", bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	b, err := bakery.NewService(bakery.NewServiceParams{})
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Bakery_:   b,
		Request:   req,
	}
	s.idp.Handle(tc)
	idptest.AssertLoginFailure(c, tc, `cannot log in: POST .*: invalid credentials`)
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderHandleBadRequest(c *gc.C) {
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1", strings.NewReader("{"))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	b, err := bakery.NewService(bakery.NewServiceParams{})
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Bakery_:   b,
		Request:   req,
	}
	s.idp.Handle(tc)
	idptest.AssertLoginFailure(c, tc, `cannot unmarshal login request: cannot unmarshal into field: cannot unmarshal request body: unexpected end of JSON input`)
}

func (s *tokenSuite) TestRegisterConfig(c *gc.C) {
	input := `
identity-providers:
 - type: keystone_token
   name: openstack3
   url: https://example.com/keystone
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(input), &conf)
	c.Assert(err, gc.IsNil)
	c.Assert(conf.IdentityProviders, gc.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), gc.Equals, "openstack3")
}
