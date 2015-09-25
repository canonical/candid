// Copyright 2015 Canonical Ltd.

package idp_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/httpbakery/form"

	extidp "github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/idp"
	"github.com/CanonicalLtd/blues-identity/internal/idtesting/mockkeystone"
	"github.com/CanonicalLtd/blues-identity/internal/keystone"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

type keystoneSuite struct {
	idpSuite
	server *mockkeystone.Server
	params *extidp.KeystoneParams
}

var _ = gc.Suite(&keystoneSuite{})

func (s *keystoneSuite) SetUpSuite(c *gc.C) {
	s.idpSuite.SetUpSuite(c)
	s.server = mockkeystone.NewServer()
	s.params = &extidp.KeystoneParams{
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
	s.idpSuite.TearDownSuite(c)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderName(c *gc.C) {
	provider := idp.NewKeystoneIdentityProvider(s.params)
	c.Assert(provider.Name(), gc.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderDescription(c *gc.C) {
	provider := idp.NewKeystoneIdentityProvider(s.params)
	c.Assert(provider.Description(), gc.Equals, "OpenStack")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderUseNameForDescription(c *gc.C) {
	provider := idp.NewKeystoneIdentityProvider(&extidp.KeystoneParams{
		Name: "openstack",
		URL:  s.server.URL,
	})
	c.Assert(provider.Description(), gc.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderInteractive(c *gc.C) {
	provider := idp.NewKeystoneIdentityProvider(s.params)
	c.Assert(provider.Interactive(), gc.Equals, true)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderURL(c *gc.C) {
	provider := idp.NewKeystoneIdentityProvider(s.params)
	tc := &testContext{}
	u, err := provider.URL(tc, "1")
	c.Assert(err, gc.IsNil)
	c.Assert(u, gc.Equals, "https://idp.test/login?waitid=1")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandleGet(c *gc.C) {
	provider := idp.NewKeystoneIdentityProvider(s.params)
	tc := &testContext{
		requestURL: "https://idp.test/login?waitid=1",
	}
	var err error
	tc.params.Request, err = http.NewRequest("GET", tc.requestURL, nil)
	c.Assert(err, gc.IsNil)
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
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
	provider := idp.NewKeystoneIdentityProvider(s.params)
	tc := &testContext{
		store:      s.store,
		requestURL: "https://idp.test/login?waitid=1",
		success:    true,
	}
	v := url.Values{
		"username": {"testuser"},
		"password": {"testpass"},
	}
	var err error
	tc.params.Request, err = http.NewRequest("POST", tc.requestURL, strings.NewReader(v.Encode()))
	c.Assert(err, gc.IsNil)
	tc.params.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
	c.Assert(tc.err, gc.IsNil)
	c.Assert(tc.macaroon, gc.Not(gc.IsNil))
	identity, err := s.store.GetIdentity(params.Username("testuser@openstack"))
	c.Assert(err, gc.IsNil)
	c.Assert(identity.ExternalID, gc.Equals, "abc@openstack")
	c.Assert(identity.Groups, jc.DeepEquals, []string{"abc_project@openstack"})
	c.Assert(rr.Body.String(), gc.Equals, "login successful as user testuser@openstack\n")
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandlePostBadPassword(c *gc.C) {
	provider := idp.NewKeystoneIdentityProvider(s.params)
	tc := &testContext{
		store:      s.store,
		requestURL: "https://idp.test/login?waitid=1",
		success:    true,
	}
	v := url.Values{
		"username": []string{"testuser"},
		"password": []string{"nottestpass"},
	}
	var err error
	tc.params.Request, err = http.NewRequest("POST", tc.requestURL, strings.NewReader(v.Encode()))
	c.Assert(err, gc.IsNil)
	tc.params.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
	c.Assert(tc.err, gc.ErrorMatches, `cannot log in: POST .*/v2.0/tokens: invalid credentials`)
	c.Assert(tc.macaroon, gc.IsNil)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandlePostNoTenants(c *gc.C) {
	provider := idp.NewKeystoneIdentityProvider(s.params)
	tc := &testContext{
		store:      s.store,
		requestURL: "https://idp.test/login?waitid=1",
		success:    true,
	}
	v := url.Values{
		"username": []string{"testuser2"},
		"password": []string{"testpass"},
	}
	var err error
	tc.params.Request, err = http.NewRequest("POST", tc.requestURL, strings.NewReader(v.Encode()))
	c.Assert(err, gc.IsNil)
	tc.params.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
	c.Assert(tc.err, gc.ErrorMatches, `cannot get tenants: GET .*/v2.0/tenants: bad token`)
	c.Assert(tc.macaroon, gc.IsNil)
}

func (s *keystoneSuite) TestKeystoneIdentityProviderHandleExistingUser(c *gc.C) {
	provider := idp.NewKeystoneIdentityProvider(s.params)
	tc := &testContext{
		store:      s.store,
		requestURL: "https://idp.test/login?waitid=1",
		success:    true,
	}
	err := s.store.UpsertIdentity(&mongodoc.Identity{
		Username:   "testuser@openstack",
		ExternalID: "some other thing",
	})
	c.Assert(err, gc.IsNil)
	v := url.Values{
		"username": []string{"testuser"},
		"password": []string{"testpass"},
	}
	tc.params.Request, err = http.NewRequest("POST", tc.requestURL, strings.NewReader(v.Encode()))
	c.Assert(err, gc.IsNil)
	tc.params.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
	c.Assert(tc.err, gc.ErrorMatches, "cannot update identity: cannot add user: duplicate username or external_id")
	c.Assert(tc.macaroon, gc.IsNil)
}

func (s *keystoneSuite) TestKeystoneUserpassIdentityProviderName(c *gc.C) {
	provider := idp.NewKeystoneUserpassIdentityProvider(s.params)
	c.Assert(provider.Name(), gc.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneUserpassIdentityProviderDescription(c *gc.C) {
	provider := idp.NewKeystoneUserpassIdentityProvider(s.params)
	c.Assert(provider.Description(), gc.Equals, "OpenStack")
}

func (s *keystoneSuite) TestKeystoneUserpassIdentityProviderUseNameForDescription(c *gc.C) {
	provider := idp.NewKeystoneUserpassIdentityProvider(&extidp.KeystoneParams{
		Name: "openstack",
		URL:  s.server.URL,
	})
	c.Assert(provider.Description(), gc.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneUserpassIdentityProviderInteractive(c *gc.C) {
	provider := idp.NewKeystoneUserpassIdentityProvider(s.params)
	c.Assert(provider.Interactive(), gc.Equals, false)
}

func (s *keystoneSuite) TestKeystoneUserpassIdentityProviderURL(c *gc.C) {
	provider := idp.NewKeystoneUserpassIdentityProvider(s.params)
	tc := &testContext{}
	u, err := provider.URL(tc, "1")
	c.Assert(err, gc.IsNil)
	c.Assert(u, gc.Equals, "https://idp.test/login?waitid=1")
}

func (s *keystoneSuite) TestKeystoneUserpassIdentityProviderHandle(c *gc.C) {
	provider := idp.NewKeystoneUserpassIdentityProvider(s.params)
	tc := &testContext{
		store:      s.store,
		requestURL: "https://idp.test/login?waitid=1",
		success:    true,
	}
	var err error
	tc.params.Request, err = http.NewRequest("GET", tc.requestURL, nil)
	c.Assert(err, gc.IsNil)
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
	c.Assert(tc.err, gc.IsNil)
	httptesting.AssertJSONResponse(c, rr, http.StatusOK, idp.KeystoneSchemaResponse)
}

func (s *keystoneSuite) TestKeystoneUserpassIdentityProviderHandleResponse(c *gc.C) {
	provider := idp.NewKeystoneUserpassIdentityProvider(s.params)
	tc := &testContext{
		store:      s.store,
		requestURL: "https://idp.test/login?waitid=1",
		success:    true,
	}
	login := map[string]interface{}{
		"username": "testuser",
		"password": "testpass",
	}
	body, err := json.Marshal(form.LoginBody{
		Form: login,
	})
	c.Assert(err, gc.IsNil)
	tc.params.Request, err = http.NewRequest("POST", tc.requestURL, bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	tc.params.Request.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
	c.Assert(tc.err, gc.IsNil)
	c.Assert(tc.macaroon, gc.Not(gc.IsNil))
	identity, err := s.store.GetIdentity(params.Username("testuser@openstack"))
	c.Assert(err, gc.IsNil)
	c.Assert(identity.ExternalID, gc.Equals, "abc@openstack")
	c.Assert(identity.Groups, jc.DeepEquals, []string{"abc_project@openstack"})
	c.Assert(rr.Body.String(), gc.Equals, "login successful as user testuser@openstack\n")
}

func (s *keystoneSuite) TestKeystoneUserpassIdentityProviderHandleBadRequest(c *gc.C) {
	provider := idp.NewKeystoneUserpassIdentityProvider(s.params)
	tc := &testContext{
		store:      s.store,
		requestURL: "https://idp.test/login?waitid=1",
	}
	var err error
	tc.params.Request, err = http.NewRequest("POST", tc.requestURL, strings.NewReader("{"))
	c.Assert(err, gc.IsNil)
	tc.params.Request.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
	c.Assert(tc.err, gc.ErrorMatches, `cannot unmarshal login request: cannot unmarshal into field: cannot unmarshal request body: unexpected end of JSON input`)
	c.Assert(tc.macaroon, gc.IsNil)
}

func (s *keystoneSuite) TestKeystoneUserpassIdentityProviderHandleNoUsername(c *gc.C) {
	provider := idp.NewKeystoneUserpassIdentityProvider(s.params)
	tc := &testContext{
		store:      s.store,
		requestURL: "https://idp.test/login?waitid=1",
	}
	login := map[string]interface{}{
		"password": "testpass",
	}
	body, err := json.Marshal(form.LoginBody{
		Form: login,
	})
	c.Assert(err, gc.IsNil)
	tc.params.Request, err = http.NewRequest("POST", tc.requestURL, bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	tc.params.Request.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
	c.Assert(tc.err, gc.ErrorMatches, `cannot validate form: username: expected string, got nothing`)
	c.Assert(tc.macaroon, gc.IsNil)
}

func (s *keystoneSuite) TestKeystoneTokenIdentityProviderName(c *gc.C) {
	provider := idp.NewKeystoneTokenIdentityProvider(s.params)
	c.Assert(provider.Name(), gc.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneTokenIdentityProviderDescription(c *gc.C) {
	provider := idp.NewKeystoneTokenIdentityProvider(s.params)
	c.Assert(provider.Description(), gc.Equals, "OpenStack")
}

func (s *keystoneSuite) TestKeystoneTokenIdentityProviderUseNameForDescription(c *gc.C) {
	provider := idp.NewKeystoneTokenIdentityProvider(&extidp.KeystoneParams{
		Name: "openstack",
		URL:  s.server.URL,
	})
	c.Assert(provider.Description(), gc.Equals, "openstack")
}

func (s *keystoneSuite) TestKeystoneTokenIdentityProviderInteractive(c *gc.C) {
	provider := idp.NewKeystoneTokenIdentityProvider(s.params)
	c.Assert(provider.Interactive(), gc.Equals, false)
}

func (s *keystoneSuite) TestKeystoneTokenIdentityProviderURL(c *gc.C) {
	provider := idp.NewKeystoneTokenIdentityProvider(s.params)
	tc := &testContext{}
	u, err := provider.URL(tc, "1")
	c.Assert(err, gc.IsNil)
	c.Assert(u, gc.Equals, "https://idp.test/login?waitid=1")
}

func (s *keystoneSuite) TestKeystoneTokenIdentityProviderHandle(c *gc.C) {
	provider := idp.NewKeystoneTokenIdentityProvider(s.params)
	tc := &testContext{
		store:      s.store,
		requestURL: "https://idp.test/login?waitid=1",
		success:    true,
	}
	var req idp.KeystoneToken
	req.Login.ID = "789"
	body, err := json.Marshal(req)
	c.Assert(err, gc.IsNil)
	tc.params.Request, err = http.NewRequest("POST", tc.requestURL, bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	tc.params.Request.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
	c.Assert(tc.err, gc.IsNil)
	c.Assert(tc.macaroon, gc.Not(gc.IsNil))
	identity, err := s.store.GetIdentity(params.Username("testuser@openstack"))
	c.Assert(err, gc.IsNil)
	c.Assert(identity.ExternalID, gc.Equals, "abc@openstack")
	c.Assert(identity.Groups, jc.DeepEquals, []string{"abc_project@openstack"})
	c.Assert(rr.Body.String(), gc.Equals, "login successful as user testuser@openstack\n")
}

func (s *keystoneSuite) TestKeystoneTokenIdentityProviderHandleBadToken(c *gc.C) {
	provider := idp.NewKeystoneTokenIdentityProvider(s.params)
	tc := &testContext{
		store:      s.store,
		requestURL: "https://idp.test/login?waitid=1",
		success:    true,
	}
	var req idp.KeystoneToken
	req.Login.ID = "012"
	body, err := json.Marshal(req)
	c.Assert(err, gc.IsNil)
	tc.params.Request, err = http.NewRequest("POST", tc.requestURL, bytes.NewReader(body))
	c.Assert(err, gc.IsNil)
	tc.params.Request.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
	c.Assert(tc.err, gc.ErrorMatches, "cannot log in: POST .*/v2.0/tokens: invalid credentials")
	c.Assert(tc.macaroon, gc.IsNil)
}

func (s *keystoneSuite) TestKeystoneTokenIdentityProviderHandleBadRequest(c *gc.C) {
	provider := idp.NewKeystoneTokenIdentityProvider(s.params)
	tc := &testContext{
		store:      s.store,
		requestURL: "https://idp.test/login?waitid=1",
		success:    true,
	}
	var err error
	tc.params.Request, err = http.NewRequest("POST", tc.requestURL, strings.NewReader("{"))
	c.Assert(err, gc.IsNil)
	tc.params.Request.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	provider.Handle(tc)
	c.Assert(tc.err, gc.ErrorMatches, "cannot unmarshal login request: cannot unmarshal into field: cannot unmarshal request body: unexpected end of JSON input")
	c.Assert(tc.macaroon, gc.IsNil)
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
