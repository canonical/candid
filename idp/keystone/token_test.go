// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	gc "gopkg.in/check.v1"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/candid/config"
	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idptest"
	keystoneidp "github.com/CanonicalLtd/candid/idp/keystone"
	"github.com/CanonicalLtd/candid/idp/keystone/internal/mockkeystone"
	"github.com/CanonicalLtd/candid/store"
)

type tokenSuite struct {
	idptest.Suite
	server *mockkeystone.Server
	params keystoneidp.Params
	idp    idp.IdentityProvider
}

var _ = gc.Suite(&tokenSuite{})

func (s *tokenSuite) SetUpSuite(c *gc.C) {
	s.Suite.SetUpSuite(c)
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
	s.Suite.TearDownSuite(c)
}

func (s *tokenSuite) SetUpTest(c *gc.C) {
	s.Suite.SetUpTest(c)
	s.idp = keystoneidp.NewTokenIdentityProvider(s.params)
	err := s.idp.Init(s.Ctx, s.InitParams(c, "https://idp.test"))
	c.Assert(err, gc.Equals, nil)
}

func (s *tokenSuite) TearDownTest(c *gc.C) {
	s.Suite.TearDownTest(c)
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, false)
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderHandle(c *gc.C) {
	var tok keystoneidp.Token
	tok.Login.ID = "789"
	body, err := json.Marshal(tok)
	c.Assert(err, gc.Equals, nil)
	req, err := http.NewRequest("POST", "https://idp.test/login?did=1", bytes.NewReader(body))
	c.Assert(err, gc.Equals, nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginSuccess(c, "testuser@openstack")
	s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("openstack", "abc@openstack"),
		Username:   "testuser@openstack",
		ProviderInfo: map[string][]string{
			"groups": {"abc_project@openstack"},
		},
	})
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderHandleBadToken(c *gc.C) {
	var tok keystoneidp.Token
	tok.Login.ID = "012"
	body, err := json.Marshal(tok)
	c.Assert(err, gc.Equals, nil)
	req, err := http.NewRequest("POST", "https://idp.test/login?did=1", bytes.NewReader(body))
	c.Assert(err, gc.Equals, nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginFailureMatches(c, `cannot log in: Post http.*: invalid credentials`)
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderHandleBadRequest(c *gc.C) {
	req, err := http.NewRequest("POST", "https://idp.test/login?did=1", strings.NewReader("{"))
	c.Assert(err, gc.Equals, nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginFailureMatches(c, `cannot unmarshal login request: cannot unmarshal into field Token: cannot unmarshal request body: unexpected end of JSON input`)
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
	c.Assert(err, gc.Equals, nil)
	c.Assert(conf.IdentityProviders, gc.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), gc.Equals, "openstack3")
}
