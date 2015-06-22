// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

type idpsSuite struct {
	apiSuite
}

var _ = gc.Suite(&idpsSuite{})

func (s *idpsSuite) TestPutIDPS(c *gc.C) {
	tests := []struct {
		about        string
		url          string
		username     string
		password     string
		idp          params.IdentityProvider
		expectStatus int
		expectBody   interface{}
	}{{
		about:    "OpenID 2.0 provider",
		url:      "idps/provider1",
		username: adminUsername,
		password: adminPassword,
		idp: params.IdentityProvider{
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		},
		expectStatus: http.StatusOK,
	}, {
		about:    "unsupported protocol provider",
		url:      "idps/provider2",
		username: adminUsername,
		password: adminPassword,
		idp: params.IdentityProvider{
			Protocol: "unsupported",
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		},
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Message: `unsupported identity protocol "unsupported"`,
			Code:    params.ErrBadRequest,
		},
	}, {
		about:    "invalid username",
		url:      "idps/provider2",
		username: "big bad wolf",
		password: adminPassword,
		idp: params.IdentityProvider{
			Name:     "provider1",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		},
		expectStatus: http.StatusUnauthorized,
		expectBody: params.Error{
			Message: `invalid credentials`,
			Code:    params.ErrUnauthorized,
		},
	}, {
		about:    "invalid password",
		url:      "idps/provider2",
		username: adminUsername,
		password: "let me in",
		idp: params.IdentityProvider{
			Name:     "provider1",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		},
		expectStatus: http.StatusUnauthorized,
		expectBody: params.Error{
			Message: `invalid credentials`,
			Code:    params.ErrUnauthorized,
		},
	}, {
		about:    "no provider name",
		url:      "idps/",
		username: adminUsername,
		password: adminPassword,
		idp: params.IdentityProvider{
			Name:     "",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		},
		expectStatus: http.StatusNotFound,
		expectBody: params.Error{
			Message: `not found: /idps/`,
			Code:    params.ErrNotFound,
		},
	}, {
		about:    "no login url",
		url:      "idps/provider2",
		username: adminUsername,
		password: adminPassword,
		idp: params.IdentityProvider{
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{},
		},
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Message: `openid.login_url not specified`,
			Code:    params.ErrBadRequest,
		},
	}, {
		about:    "login url wrong type",
		url:      "idps/provider2",
		username: adminUsername,
		password: adminPassword,
		idp: params.IdentityProvider{
			Name:     "provider1",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: 43.4,
			},
		},
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Message: `openid.login_url not specified`,
			Code:    params.ErrBadRequest,
		},
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler: s.srv,
			Method:  "PUT",
			URL:     apiURL(test.url),
			Body:    marshal(c, test.idp),
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			Username:     test.username,
			Password:     test.password,
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectBody,
		})
	}
}

func (s *idpsSuite) TestGetIDPS(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	provider1 := &mongodoc.IdentityProvider{
		Name:     "provider1",
		Protocol: params.ProtocolOpenID20,
		LoginURL: "https://login.example.com",
	}
	err := store.SetIdentityProvider(provider1)
	c.Assert(err, gc.Equals, nil)
	tests := []struct {
		about    string
		provider string
		status   int
		result   interface{}
	}{{
		about:    "OpenID 2.0 provider",
		provider: "provider1",
		status:   http.StatusOK,
		result: params.IdentityProvider{
			Name:     "provider1",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		},
	}, {
		about:    "unknown provider",
		provider: "provider2",
		status:   http.StatusNotFound,
		result: params.Error{
			Message: `cannot get identity provider "provider2": not found`,
			Code:    params.ErrNotFound,
		},
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:      s.srv,
			Method:       "GET",
			URL:          fmt.Sprintf("/%s/idps/%s", version, test.provider),
			ExpectStatus: test.status,
			ExpectBody:   test.result,
		})
	}
}

func (s *idpsSuite) TestListIDPS(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:    s.srv,
		Method:     "GET",
		URL:        fmt.Sprintf("/%s/idps", version),
		ExpectBody: []string{},
	})
	err := store.SetIdentityProvider(
		&mongodoc.IdentityProvider{
			Name:     "idp1",
			Protocol: params.ProtocolOpenID20,
			LoginURL: "https://login.example.com",
		},
	)
	c.Assert(err, gc.Equals, nil)
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:    s.srv,
		Method:     "GET",
		URL:        fmt.Sprintf("/%s/idps", version),
		ExpectBody: []string{"idp1"},
	})
	err = store.SetIdentityProvider(
		&mongodoc.IdentityProvider{
			Name:     "idp2",
			Protocol: params.ProtocolOpenID20,
			LoginURL: "https://login.example.com",
		},
	)
	c.Assert(err, gc.Equals, nil)
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:    s.srv,
		Method:     "GET",
		URL:        fmt.Sprintf("/%s/idps", version),
		ExpectBody: []string{"idp1", "idp2"},
	})
}

// marshal converts a value into a bytes.Reader containing the json
// encoding of that value.
func marshal(c *gc.C, v interface{}) *bytes.Reader {
	b, err := json.Marshal(v)
	c.Assert(err, gc.Equals, nil)
	return bytes.NewReader(b)
}
