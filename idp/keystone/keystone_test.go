// Copyright 2015 Canonical Ltd.

package keystone_test

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/juju/idmclient/params"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	keystoneidp "github.com/CanonicalLtd/blues-identity/idp/keystone"
	"github.com/CanonicalLtd/blues-identity/idp/keystone/internal/keystone"
	"github.com/CanonicalLtd/blues-identity/idp/keystone/internal/mockkeystone"
)

type keystoneSuite struct {
	server *mockkeystone.Server
	params keystoneidp.Params
	idp    idp.IdentityProvider
}

var _ = gc.Suite(&keystoneSuite{})

func (s *keystoneSuite) SetUpSuite(c *gc.C) {
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

func (s *keystoneSuite) TearDownSuite(c *gc.C) {
	s.server.Close()
}

func (s *keystoneSuite) SetUpTest(c *gc.C) {
	s.idp = keystoneidp.NewIdentityProvider(s.params)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderName(c *gc.C) {
	c.Assert(s.idp.Name(), gc.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderDescription(c *gc.C) {
	c.Assert(s.idp.Description(), gc.Equals, "OpenStack")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, true)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderUseNameForDescription(c *gc.C) {
	p := s.params
	p.Description = ""
	idp := keystoneidp.NewIdentityProvider(p)
	c.Assert(idp.Description(), gc.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderURL(c *gc.C) {
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
	}
	u, err := s.idp.URL(tc, "1")
	c.Assert(err, gc.IsNil)
	c.Assert(u, gc.Equals, "https://idp.test/login?waitid=1")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandleGet(c *gc.C) {
	req, err := http.NewRequest("GET", "https://idp.test/login?waitid=1", nil)
	c.Assert(err, gc.IsNil)
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Request:   req,
	}
	s.idp.Handle(tc)
	idptest.AssertLoginInProgress(c, tc)
	rr := tc.Response()
	c.Assert(rr.Code, gc.Equals, http.StatusOK)
	c.Assert(rr.HeaderMap.Get("Content-Type"), gc.Equals, "text/html;charset=UTF-8")
	c.Assert(rr.Body.String(), gc.Equals, `<!doctype html>
<html>
	<head><title>OpenStack Login</title></head>
	<body>
		<form method="POST" action="https://idp.test/login?waitid=1">
			<p><label>Username: <input type="text" name="username"></label></p>
			<p><label>Password: <input type="password" name="password"></label></p>
			<p><input type="submit"></p>
		</form>
	</body>
</html>
`)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandlePost(c *gc.C) {
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1",
		strings.NewReader(
			url.Values{
				"username": {"testuser"},
				"password": {"testpass"},
			}.Encode(),
		),
	)
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b, err := bakery.NewService(bakery.NewServiceParams{})
	c.Assert(err, gc.IsNil)
	tc := &idptest.TestContext{

		Request: req,
		Bakery_: b,
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

func (s *keystoneSuite) TestKeystoneIdentityProviderHandlePostBadPassword(c *gc.C) {
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1",
		strings.NewReader(
			url.Values{
				"username": {"testuser"},
				"password": {"nottestpass"},
			}.Encode(),
		),
	)
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b, err := bakery.NewService(bakery.NewServiceParams{})
	c.Assert(err, gc.IsNil)
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Request:   req,
		Bakery_:   b,
	}
	s.idp.Handle(tc)
	idptest.AssertLoginFailure(c, tc, `cannot log in: invalid credentials`)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandlePostNoTenants(c *gc.C) {
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1",
		strings.NewReader(
			url.Values{
				"username": {"testuser2"},
				"password": {"testpass"},
			}.Encode(),
		),
	)
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b, err := bakery.NewService(bakery.NewServiceParams{})
	c.Assert(err, gc.IsNil)
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Request:   req,
		Bakery_:   b,
	}
	s.idp.Handle(tc)
	idptest.AssertLoginFailure(c, tc, `cannot get tenants: bad token`)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandleExistingUser(c *gc.C) {
	req, err := http.NewRequest("POST", "https://idp.test/login?waitid=1",
		strings.NewReader(
			url.Values{
				"username": {"testuser"},
				"password": {"testpass"},
			}.Encode(),
		),
	)
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b, err := bakery.NewService(bakery.NewServiceParams{})
	c.Assert(err, gc.IsNil)
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Request:   req,
		Bakery_:   b,
	}
	err = tc.UpdateUser(&params.User{
		Username:   params.Username("testuser@openstack"),
		ExternalID: "some other thing",
	})
	s.idp.Handle(tc)
	idptest.AssertLoginFailure(c, tc, `cannot update identity: username "testuser@openstack" already used`)
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

func (s *keystoneSuite) TestKeystoneIdentityProviderRegisterConfig(c *gc.C) {
	for i, test := range configTests {
		c.Logf("%d. %s", i, test.about)
		var conf config.Config
		err := yaml.Unmarshal([]byte(test.yaml), &conf)
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			continue
		}
		c.Assert(err, gc.IsNil)
		c.Assert(conf.IdentityProviders, gc.HasLen, 1)
		c.Assert(conf.IdentityProviders[0].Name(), gc.Equals, "openstack")
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
