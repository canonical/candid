// Copyright 2015 Canonical Ltd.

package keystone_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	gc "gopkg.in/check.v1"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	keystoneidp "github.com/CanonicalLtd/blues-identity/idp/keystone"
	"github.com/CanonicalLtd/blues-identity/idp/keystone/internal/mockkeystone"
	"github.com/CanonicalLtd/blues-identity/store"
)

type tokenV3Suite struct {
	idptest.Suite
	server *mockkeystone.Server
	params keystoneidp.Params
	idp    idp.IdentityProvider
}

var _ = gc.Suite(&tokenV3Suite{})

func (s *tokenV3Suite) SetUpTest(c *gc.C) {
	s.Suite.SetUpTest(c)
	s.server = mockkeystone.NewServer()
	s.params = keystoneidp.Params{
		Name:        "openstack",
		Description: "OpenStack",
		Domain:      "openstack",
		URL:         s.server.URL,
	}
	s.server.AuthTokensFunc = testAuthTokens
	s.server.UserGroupsFunc = testUserGroups
	s.idp = keystoneidp.NewV3TokenIdentityProvider(s.params)
	err := s.idp.Init(s.Ctx, s.InitParams(c, "https://idp.test"))
	c.Assert(err, gc.Equals, nil)
}

func (s *tokenV3Suite) TearDownTest(c *gc.C) {
	s.server.Close()
	s.Suite.TearDownTest(c)
}

func (s *tokenV3Suite) TestKeystoneV3TokenIdentityProviderInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, false)
}

func (s *tokenV3Suite) TestKeystoneV3TokenIdentityProviderHandle(c *gc.C) {
	var tok keystoneidp.Token
	tok.Login.ID = "789"
	body, err := json.Marshal(tok)
	c.Assert(err, gc.IsNil)
	req, err := http.NewRequest("POST", "/login?waitid=1", bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginSuccess(c, "testuser@openstack")
	s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("openstack", "123@openstack"),
		Username:   "testuser@openstack",
		Groups:     []string{"abc_group@openstack"},
	})
}

func (s *tokenV3Suite) TestKeystoneV3TokenIdentityProviderHandleBadToken(c *gc.C) {
	var tok keystoneidp.Token
	tok.Login.ID = "012"
	body, err := json.Marshal(tok)
	c.Assert(err, gc.IsNil)
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1", bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginFailureMatches(c, `cannot log in: Post http.*: The request you have made requires authentication.`)
}

func (s *tokenV3Suite) TestKeystoneV3TokenIdentityProviderHandleBadRequest(c *gc.C) {
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1", strings.NewReader("{"))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.idp.Handle(s.Ctx, rr, req)
	s.AssertLoginFailureMatches(c, `cannot unmarshal login request: cannot unmarshal into field Token: cannot unmarshal request body: unexpected end of JSON input`)
}

func (s *tokenV3Suite) TestRegisterConfig(c *gc.C) {
	input := `
identity-providers:
 - type: keystonev3_token
   name: openstackv3_3
   url: https://example.com/keystone
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(input), &conf)
	c.Assert(err, gc.IsNil)
	c.Assert(conf.IdentityProviders, gc.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), gc.Equals, "openstackv3_3")
}
