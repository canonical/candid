// Copyright 2015 Canonical Ltd.

package keystone_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/juju/idmclient/params"
	"github.com/juju/testing/httptesting"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery/form"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	keystoneidp "github.com/CanonicalLtd/blues-identity/idp/keystone"
	"github.com/CanonicalLtd/blues-identity/idp/keystone/internal/mockkeystone"
)

type userpassSuite struct {
	server *mockkeystone.Server
	params keystoneidp.Params
	idp    idp.IdentityProvider
}

var _ = gc.Suite(&userpassSuite{})

func (s *userpassSuite) SetUpSuite(c *gc.C) {
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
}

func (s *userpassSuite) SetUpTest(c *gc.C) {
	s.idp = keystoneidp.NewUserpassIdentityProvider(s.params)
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, false)
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHandle(c *gc.C) {
	req, err := http.NewRequest("GET", "https://idp.test/login?waitid=1", nil)
	c.Assert(err, gc.IsNil)
	tc := &idptest.TestContext{
		Context: context.Background(),
		Request: req,
	}
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	idptest.AssertLoginInProgress(c, tc)
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
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1", bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: "https://idp.test",
		Bakery_:   bakery.New(bakery.BakeryParams{}),
		Request:   req,
	}
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	idptest.AssertLoginSuccess(c, tc, "testuser@openstack")
	idptest.AssertUser(c, tc, &params.User{
		Username:   params.Username("testuser@openstack"),
		ExternalID: "abc@openstack",
		IDPGroups:  []string{"abc_project@openstack"},
	})
	c.Assert(rr.Body.String(), gc.Equals, "login successful as user testuser@openstack\n")
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHandleBadRequest(c *gc.C) {
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1", strings.NewReader("{"))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: "https://idp.test",
		Bakery_:   bakery.New(bakery.BakeryParams{}),
		Request:   req,
	}
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	idptest.AssertLoginFailure(c, tc, `cannot unmarshal login request: cannot unmarshal into field Body: cannot unmarshal request body: unexpected end of JSON input`)
}

func (s *userpassSuite) TestKeystoneUserpassIdentityProviderHandleNoUsername(c *gc.C) {
	login := map[string]interface{}{
		"password": "testpass",
	}
	body, err := json.Marshal(form.LoginBody{
		Form: login,
	})
	c.Assert(err, gc.IsNil)
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1", bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: "https://idp.test",
		Bakery_:   bakery.New(bakery.BakeryParams{}),
		Request:   req,
	}
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	idptest.AssertLoginFailure(c, tc, `cannot validate form: username: expected string, got nothing`)
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
