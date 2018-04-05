// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery/form"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/candid/config"
	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idptest"
	keystoneidp "github.com/CanonicalLtd/candid/idp/keystone"
	"github.com/CanonicalLtd/candid/idp/keystone/internal/mockkeystone"
	"github.com/CanonicalLtd/candid/store"
)

type userpassSuite struct {
	idptest.Suite
	server *mockkeystone.Server
	params keystoneidp.Params
	idp    idp.IdentityProvider
}

var _ = gc.Suite(&userpassSuite{})

func (s *userpassSuite) SetUpSuite(c *gc.C) {
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

func (s *userpassSuite) TearDownSuite(c *gc.C) {
	s.server.Close()
	s.Suite.TearDownSuite(c)
}

func (s *userpassSuite) SetUpTest(c *gc.C) {
	s.Suite.SetUpTest(c)
	s.idp = keystoneidp.NewUserpassIdentityProvider(s.params)
	err := s.idp.Init(s.Ctx, s.InitParams(c, "https://idp.test"))
	c.Assert(err, gc.Equals, nil)
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, false)
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHandle(c *gc.C) {
	req, err := http.NewRequest("GET", "https://idp.test/login?did=1", nil)
	c.Assert(err, gc.Equals, nil)
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginNotComplete(c)
	httptesting.AssertJSONResponse(c, rr, http.StatusOK, keystoneidp.KeystoneSchemaResponse)
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHandleResponse(c *gc.C) {
	login := map[string]interface{}{
		"username": "testuser",
		"password": "testpass",
	}
	body, err := json.Marshal(form.LoginBody{
		Form: login,
	})
	c.Assert(err, gc.IsNil)
	req, err := http.NewRequest("POST", "/login?did=1", bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginSuccess(c, "testuser@openstack")
	identity := s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("openstack", "abc@openstack"),
		Username:   "testuser@openstack",
		ProviderInfo: map[string][]string{
			"groups": {"abc_project@openstack"},
		},
	})
	groups, err := s.idp.GetGroups(s.Ctx, identity)
	c.Assert(err, gc.Equals, nil)
	c.Assert(groups, gc.DeepEquals, []string{"abc_project@openstack"})
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHandleBadRequest(c *gc.C) {
	req, err := http.NewRequest("POST", "/login?did=1", strings.NewReader("{"))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginFailureMatches(c, `cannot unmarshal login request: cannot unmarshal into field Body: cannot unmarshal request body: unexpected end of JSON input`)
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHandleNoUsername(c *gc.C) {
	login := map[string]interface{}{
		"password": "testpass",
	}
	body, err := json.Marshal(form.LoginBody{
		Form: login,
	})
	c.Assert(err, gc.IsNil)
	req, err := http.NewRequest("POST", "https://idp.test/login?did=1", bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginFailureMatches(c, `cannot validate form: username: expected string, got nothing`)
}

func (s *userpassSuite) TestRegisterConfig(c *gc.C) {
	input := `
identity-providers:
 - type: keystone_userpass
   name: openstack2
   url: https://example.com/keystone
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(input), &conf)
	c.Assert(err, gc.IsNil)
	c.Assert(conf.IdentityProviders, gc.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), gc.Equals, "openstack2")
}
