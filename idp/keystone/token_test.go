// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"gopkg.in/yaml.v2"

	"github.com/canonical/candid/config"
	keystoneidp "github.com/canonical/candid/idp/keystone"
	"github.com/canonical/candid/store"
)

type tokenSuite struct {
	*fixture
}

func TestToken(t *testing.T) {
	qtsuite.Run(qt.New(t), &tokenSuite{})
}

func (s *tokenSuite) Init(c *qt.C) {
	s.fixture = newFixture(c, fixtureParams{
		newIDP:      keystoneidp.NewTokenIdentityProvider,
		tokensFunc:  testTokens,
		tenantsFunc: testTenants,
	})
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderInteractive(c *qt.C) {
	c.Assert(s.idp.Interactive(), qt.Equals, false)
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderHidden(c *qt.C) {
	c.Assert(s.idp.Hidden(), qt.Equals, false)
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderHandle(c *qt.C) {
	var tok keystoneidp.Token
	tok.Login.ID = "789"
	body, err := json.Marshal(tok)
	c.Assert(err, qt.IsNil)
	req, err := http.NewRequest("POST", "https://idp.test/login?did=1", bytes.NewReader(body))
	c.Assert(err, qt.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginSuccess(c, "testuser@openstack")
	s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("openstack", "abc@openstack"),
		Username:   "testuser@openstack",
		ProviderInfo: map[string][]string{
			"groups": {"abc_project"},
		},
	})
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderHandleBadToken(c *qt.C) {
	var tok keystoneidp.Token
	tok.Login.ID = "012"
	body, err := json.Marshal(tok)
	c.Assert(err, qt.IsNil)
	req, err := http.NewRequest("POST", "https://idp.test/login?did=1", bytes.NewReader(body))
	c.Assert(err, qt.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginFailureMatches(c, `cannot log in: Post http.*: invalid credentials`)
}

func (s *tokenSuite) TestKeystoneTokenIdentityProviderHandleBadRequest(c *qt.C) {
	req, err := http.NewRequest("POST", "https://idp.test/login?did=1", strings.NewReader("{"))
	c.Assert(err, qt.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginFailureMatches(c, `cannot unmarshal login request: cannot unmarshal into field Token: cannot unmarshal request body: unexpected end of JSON input`)
}

func (s *tokenSuite) TestRegisterConfig(c *qt.C) {
	input := `
identity-providers:
 - type: keystone_token
   name: openstack3
   url: https://example.com/keystone
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(input), &conf)
	c.Assert(err, qt.IsNil)
	c.Assert(conf.IdentityProviders, qt.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), qt.Equals, "openstack3")
}
