// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/candid/config"
	"github.com/CanonicalLtd/candid/idp"
	keystoneidp "github.com/CanonicalLtd/candid/idp/keystone"
	"github.com/CanonicalLtd/candid/idp/keystone/internal/keystone"
	"github.com/CanonicalLtd/candid/idp/keystone/internal/mockkeystone"
	idptest "github.com/CanonicalLtd/candid/idp/qtidptest"
	candidtest "github.com/CanonicalLtd/candid/internal/qtcandidtest"
	"github.com/CanonicalLtd/candid/store"
)

type keystoneSuite struct {
	idptest *idptest.Fixture
	server  *mockkeystone.Server
	params  keystoneidp.Params
	idp     idp.IdentityProvider
}

func TestKeystone(t *testing.T) {
	qtsuite.Run(qt.New(t), &keystoneSuite{})
}

func (s *keystoneSuite) Init(c *qt.C) {
	s.idptest = idptest.NewFixture(c, candidtest.NewStore())
	s.server = mockkeystone.NewServer()
	c.Defer(s.server.Close)
	s.params = keystoneidp.Params{
		Name:        "openstack",
		Description: "OpenStack",
		Domain:      "openstack",
		URL:         s.server.URL,
	}
	s.server.TokensFunc = testTokens
	s.server.TenantsFunc = testTenants
	s.idp = keystoneidp.NewIdentityProvider(s.params)
	err := s.idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, "https://idp.test"))
	c.Assert(err, qt.Equals, nil)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderName(c *qt.C) {
	c.Assert(s.idp.Name(), qt.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderDescription(c *qt.C) {
	c.Assert(s.idp.Description(), qt.Equals, "OpenStack")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderInteractive(c *qt.C) {
	c.Assert(s.idp.Interactive(), qt.Equals, true)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderUseNameForDescription(c *qt.C) {
	p := s.params
	p.Description = ""
	idp := keystoneidp.NewIdentityProvider(p)
	c.Assert(idp.Description(), qt.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderURL(c *qt.C) {
	u := s.idp.URL("1")
	c.Assert(u, qt.Equals, "https://idp.test/login?id=1")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandleGet(c *qt.C) {
	req, err := http.NewRequest("GET", "/login?id=1", nil)
	c.Assert(err, qt.Equals, nil)
	req.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginNotComplete(c)
	c.Assert(rr.Code, qt.Equals, http.StatusOK)
	c.Assert(rr.HeaderMap.Get("Content-Type"), qt.Equals, "text/html;charset=UTF-8")
	c.Assert(rr.Body.String(), qt.Equals, `<!doctype html>
<html>
	<head><title>OpenStack Login</title></head>
	<body>
		<form method="POST" action="https://idp.test/login?id=1">
			<p><label>Username: <input type="text" name="username"></label></p>
			<p><label>Password: <input type="password" name="password"></label></p>
			<p><input type="submit"></p>
		</form>
	</body>
</html>
`)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandlePost(c *qt.C) {
	req, err := http.NewRequest("POST", "/login?did=1",
		strings.NewReader(
			url.Values{
				"username": {"testuser"},
				"password": {"testpass"},
			}.Encode(),
		),
	)
	c.Assert(err, qt.Equals, nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginSuccess(c, "testuser@openstack")
	s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("openstack", "abc@openstack"),
		Username:   "testuser@openstack",
		ProviderInfo: map[string][]string{
			"groups": {"abc_project@openstack"},
		},
	})
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandlePostBadPassword(c *qt.C) {
	req, err := http.NewRequest("POST", "/login?did=1",
		strings.NewReader(
			url.Values{
				"username": {"testuser"},
				"password": {"nottestpass"},
			}.Encode(),
		),
	)
	c.Assert(err, qt.Equals, nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginFailureMatches(c, `cannot log in: Post http.*: invalid credentials`)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandlePostNoTenants(c *qt.C) {
	req, err := http.NewRequest("POST", "/login?did=1",
		strings.NewReader(
			url.Values{
				"username": {"testuser2"},
				"password": {"testpass"},
			}.Encode(),
		),
	)
	c.Assert(err, qt.Equals, nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginFailureMatches(c, `cannot get tenants: Get .*: bad token`)
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
	c.Assert(err, qt.Equals, nil)
	req, err := http.NewRequest("POST", "/login?did=1",
		strings.NewReader(
			url.Values{
				"username": {"testuser"},
				"password": {"testpass"},
			}.Encode(),
		),
	)
	c.Assert(err, qt.Equals, nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginFailureMatches(c, `cannot update identity: username testuser@openstack already in use`)
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
			c.Assert(err, qt.Equals, nil)
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
