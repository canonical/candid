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
	"github.com/juju/qthttptest"
	"gopkg.in/macaroon-bakery.v2/httpbakery/form"
	"gopkg.in/yaml.v2"

	"github.com/canonical/candid/config"
	keystoneidp "github.com/canonical/candid/idp/keystone"
	"github.com/canonical/candid/store"
)

func TestUserPass(t *testing.T) {
	qtsuite.Run(qt.New(t), &userpassSuite{})
}

type userpassSuite struct {
	*fixture
}

func (s *userpassSuite) Init(c *qt.C) {
	s.fixture = newFixture(c, fixtureParams{
		newIDP:      keystoneidp.NewUserpassIdentityProvider,
		tokensFunc:  testTokens,
		tenantsFunc: testTenants,
	})
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderInteractive(c *qt.C) {
	c.Assert(s.idp.Interactive(), qt.Equals, false)
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHidden(c *qt.C) {
	c.Assert(s.idp.Hidden(), qt.Equals, false)
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHandle(c *qt.C) {
	req, err := http.NewRequest("GET", "https://idp.test/login?did=1", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginNotComplete(c)
	qthttptest.AssertJSONResponse(c, rr, http.StatusOK, keystoneidp.KeystoneSchemaResponse)
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHandleResponse(c *qt.C) {
	login := map[string]interface{}{
		"username": "testuser",
		"password": "testpass",
	}
	body, err := json.Marshal(form.LoginBody{
		Form: login,
	})
	c.Assert(err, qt.IsNil)
	req, err := http.NewRequest("POST", "/login?did=1", bytes.NewReader(body))
	c.Assert(err, qt.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginSuccess(c, "testuser@openstack")
	identity := s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("openstack", "abc@openstack"),
		Username:   "testuser@openstack",
		ProviderInfo: map[string][]string{
			"groups": {"abc_project"},
		},
	})
	groups, err := s.idp.GetGroups(s.idptest.Ctx, identity)
	c.Assert(err, qt.IsNil)
	c.Assert(groups, qt.DeepEquals, []string{"abc_project"})
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHandleBadRequest(c *qt.C) {
	req, err := http.NewRequest("POST", "/login?did=1", strings.NewReader("{"))
	c.Assert(err, qt.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginFailureMatches(c, `cannot unmarshal login request: cannot unmarshal into field Body: cannot unmarshal request body: unexpected end of JSON input`)
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHandleNoUsername(c *qt.C) {
	login := map[string]interface{}{
		"password": "testpass",
	}
	body, err := json.Marshal(form.LoginBody{
		Form: login,
	})
	c.Assert(err, qt.IsNil)
	req, err := http.NewRequest("POST", "https://idp.test/login?did=1", bytes.NewReader(body))
	c.Assert(err, qt.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginFailureMatches(c, `cannot validate form: username: expected string, got nothing`)
}

func (s *userpassSuite) TestRegisterConfig(c *qt.C) {
	input := `
identity-providers:
 - type: keystone_userpass
   name: openstack2
   url: https://example.com/keystone
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(input), &conf)
	c.Assert(err, qt.IsNil)
	c.Assert(conf.IdentityProviders, qt.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), qt.Equals, "openstack2")
}
