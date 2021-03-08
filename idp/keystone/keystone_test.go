// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone_test

import (
	"net/http"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	yaml "gopkg.in/yaml.v2"

	"gopkg.in/canonical/candid.v2/config"
	keystoneidp "gopkg.in/canonical/candid.v2/idp/keystone"
	"gopkg.in/canonical/candid.v2/idp/keystone/internal/keystone"
	"gopkg.in/canonical/candid.v2/internal/candidtest"
	"gopkg.in/canonical/candid.v2/store"
)

type keystoneSuite struct {
	*fixture
}

func TestKeystone(t *testing.T) {
	qtsuite.Run(qt.New(t), &keystoneSuite{})
}

func (s *keystoneSuite) Init(c *qt.C) {
	s.fixture = newFixture(c, fixtureParams{
		newIDP:      keystoneidp.NewIdentityProvider,
		tokensFunc:  testTokens,
		tenantsFunc: testTenants,
	})
}

func (s *keystoneSuite) TestKeystoneIdentityProviderName(c *qt.C) {
	c.Assert(s.idp.Name(), qt.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderDescription(c *qt.C) {
	c.Assert(s.idp.Description(), qt.Equals, "OpenStack")
}

func (s *keystoneSuite) TestIconURL(c *qt.C) {
	idp := keystoneidp.NewIdentityProvider(keystoneidp.Params{})
	params := s.idptest.InitParams(c, idpPrefix)
	params.Location = "https://www.example.com/candid"
	err := idp.Init(s.idptest.Ctx, params)
	c.Assert(err, qt.IsNil)
	c.Assert(idp.IconURL(), qt.Equals, "https://www.example.com/candid/static/images/icons/keystone.svg")
}

func (s *keystoneSuite) TestAbsoluteIconURL(c *qt.C) {
	idp := keystoneidp.NewIdentityProvider(keystoneidp.Params{
		Icon: "https://www.example.com/icon.bmp",
	})
	err := idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, idpPrefix))
	c.Assert(err, qt.IsNil)
	c.Assert(idp.IconURL(), qt.Equals, "https://www.example.com/icon.bmp")
}

func (s *keystoneSuite) TestRelativeIconURL(c *qt.C) {
	idp := keystoneidp.NewIdentityProvider(keystoneidp.Params{
		Icon: "/static/icon.bmp",
	})
	params := s.idptest.InitParams(c, idpPrefix)
	params.Location = "https://www.example.com/candid"
	err := idp.Init(s.idptest.Ctx, params)
	c.Assert(err, qt.IsNil)
	c.Assert(idp.IconURL(), qt.Equals, "https://www.example.com/candid/static/icon.bmp")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderInteractive(c *qt.C) {
	c.Assert(s.idp.Interactive(), qt.Equals, true)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHidden(c *qt.C) {
	c.Assert(s.idp.Hidden(), qt.Equals, false)

	p := s.params
	p.Hidden = true
	idp := keystoneidp.NewIdentityProvider(p)
	c.Assert(idp.Hidden(), qt.Equals, true)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderUseNameForDescription(c *qt.C) {
	p := s.params
	p.Description = ""
	idp := keystoneidp.NewIdentityProvider(p)
	c.Assert(idp.Description(), qt.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderURL(c *qt.C) {
	u := s.idp.URL("1")
	c.Assert(u, qt.Equals, idpPrefix+"/login?state=1")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandleSuccess(c *qt.C) {
	id, err := s.idptest.DoInteractiveLogin(c, s.idp, idpPrefix+"/login", candidtest.PostLoginForm("testuser", "testpass"))
	c.Assert(err, qt.IsNil)
	candidtest.AssertEqualIdentity(c, id, &store.Identity{
		ProviderID: store.MakeProviderIdentity("openstack", "abc@openstack"),
		Username:   "testuser@openstack",
		ProviderInfo: map[string][]string{
			"groups": {"abc_project"},
		},
	})
	s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("openstack", "abc@openstack"),
		Username:   "testuser@openstack",
		ProviderInfo: map[string][]string{
			"groups": {"abc_project"},
		},
	})
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandlePostBadPassword(c *qt.C) {
	_, err := s.idptest.DoInteractiveLogin(c, s.idp, idpPrefix+"/login", candidtest.PostLoginForm("testuser", "nottestpass"))
	c.Assert(err, qt.ErrorMatches, `cannot log in: Post http.*: invalid credentials`)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandlePostNoTenants(c *qt.C) {
	_, err := s.idptest.DoInteractiveLogin(c, s.idp, idpPrefix+"/login", candidtest.PostLoginForm("testuser2", "testpass"))
	c.Assert(err, qt.ErrorMatches, `cannot get tenants: Get .*: bad token`)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandleExistingUser(c *qt.C) {
	err := s.idptest.Store.Store.UpdateIdentity(
		s.idptest.Ctx,
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("keystone2", "testuser@openstack"),
			Username:   "testuser@openstack",
		},
		store.Update{
			store.Username: store.Set,
		},
	)
	c.Assert(err, qt.IsNil)

	_, err = s.idptest.DoInteractiveLogin(c, s.idp, idpPrefix+"/login", candidtest.PostLoginForm("testuser", "testpass"))
	c.Assert(err, qt.ErrorMatches, `cannot update identity: username testuser@openstack already in use`)
}

var configTests = []struct {
	about       string
	yaml        string
	expectError string
}{{
	about: "good config",
	yaml: `
identity-providers:
 - type: keystone
   name: openstack
   url: https://example.com/keystone
`,
}, {
	about: "no name",
	yaml: `
identity-providers:
 - type: keystone
   url: https://example.com/keystone
`,
	expectError: `cannot unmarshal keystone configuration: name not specified`,
}, {
	about: "no url",
	yaml: `
identity-providers:
 - type: keystone
   name: openstack
`,
	expectError: `cannot unmarshal keystone configuration: url not specified`,
}}

func (s *keystoneSuite) TestKeystoneIdentityProviderRegisterConfig(c *qt.C) {
	for _, test := range configTests {
		c.Run(test.about, func(c *qt.C) {
			var conf config.Config
			err := yaml.Unmarshal([]byte(test.yaml), &conf)
			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				return
			}
			c.Assert(err, qt.IsNil)
			c.Assert(conf.IdentityProviders, qt.HasLen, 1)
			c.Assert(conf.IdentityProviders[0].Name(), qt.Equals, "openstack")
		})
	}
}

func testTokens(r *keystone.TokensRequest) (*keystone.TokensResponse, error) {
	var id string
	var username string
	if r.Body.Auth.PasswordCredentials != nil {
		switch r.Body.Auth.PasswordCredentials.Username {
		case "testuser":
			id = "123"
		case "testuser2":
			id = "456"
		default:
			return nil, &keystone.Error{
				Code:    http.StatusUnauthorized,
				Message: "invalid credentials",
				Title:   "Unauthorized",
			}
		}
		if r.Body.Auth.PasswordCredentials.Password != "testpass" {
			return nil, &keystone.Error{
				Code:    http.StatusUnauthorized,
				Message: "invalid credentials",
				Title:   "Unauthorized",
			}
		}
		username = r.Body.Auth.PasswordCredentials.Username
	} else {
		if r.Body.Auth.Token.ID != "789" {
			return nil, &keystone.Error{
				Code:    http.StatusUnauthorized,
				Message: "invalid credentials",
				Title:   "Unauthorized",
			}
		}
		id = "123"
		username = "testuser"
	}
	return &keystone.TokensResponse{
		Access: keystone.Access{
			Token: keystone.Token{
				ID: id,
			},
			User: keystone.User{
				ID:       "abc",
				Username: username,
				Name:     "Test User",
			},
		},
	}, nil
}

func testTenants(r *keystone.TenantsRequest) (*keystone.TenantsResponse, error) {
	if r.AuthToken != "123" {
		return nil, &keystone.Error{
			Code:    http.StatusUnauthorized,
			Message: "bad token",
			Title:   "Unauthorized",
		}
	}
	return &keystone.TenantsResponse{
		Tenants: []keystone.Tenant{{
			ID:   "def",
			Name: "abc_project",
		}},
	}, nil
}

func testAuthTokens(req *keystone.AuthTokensRequest) (*keystone.AuthTokensResponse, error) {
	var id string
	var username string
	if req.Body.Auth.Identity.Password != nil {
		return nil, &keystone.Error{
			Code:    http.StatusUnauthorized,
			Message: "password authentication not yet supported.",
			Title:   "Not Authorized",
		}
	} else {
		if req.Body.Auth.Identity.Token.ID != "789" {
			return nil, &keystone.Error{
				Code:    http.StatusUnauthorized,
				Message: "The request you have made requires authentication.",
				Title:   "Not Authorized",
			}
		}
		id = "123"
		username = "testuser"
	}
	return &keystone.AuthTokensResponse{
		SubjectToken: "abcd",
		Token: keystone.TokenV3{
			User: keystone.User{
				ID:   id,
				Name: username,
				Domain: &keystone.Domain{
					ID:   "default",
					Name: "Default",
				},
			},
		},
	}, nil
}

func testUserGroups(req *keystone.UserGroupsRequest) (*keystone.UserGroupsResponse, error) {
	if req.AuthToken != "abcd" {
		return nil, &keystone.Error{
			Code:    http.StatusUnauthorized,
			Message: "bad token",
			Title:   "Unauthorized",
		}
	}
	return &keystone.UserGroupsResponse{
		Groups: []keystone.Group{{
			ID:       "def",
			Name:     "abc_group",
			DomainID: "default",
		}},
	}, nil
}
