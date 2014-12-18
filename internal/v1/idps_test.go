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

func (s *apiSuite) TestPutIDPS(c *gc.C) {
	tests := []struct {
		about    string
		username string
		password string
		idp      params.IdentityProvider
		status   int
		result   interface{}
	}{{
		about:    "OpenID 2.0 provider",
		username: adminUsername,
		password: adminPassword,
		idp: params.IdentityProvider{
			Name:     "provider1",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		},
		status: http.StatusOK,
		result: true,
	}, {
		about:    "unsupported protocol provider",
		username: adminUsername,
		password: adminPassword,
		idp: params.IdentityProvider{
			Name:     "provider1",
			Protocol: "unsupported",
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		},
		status: http.StatusBadRequest,
		result: params.Error{
			Message: `unsupported identity protocol "unsupported"`,
			Code:    params.ErrBadRequest,
		},
	}, {
		about:    "invalid username",
		username: "big bad wolfe",
		password: adminPassword,
		idp: params.IdentityProvider{
			Name:     "provider1",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		},
		status: http.StatusUnauthorized,
		result: params.Error{
			Message: `invalid credentials`,
			Code:    params.ErrUnauthorized,
		},
	}, {
		about:    "invalid password",
		username: adminUsername,
		password: "let me in",
		idp: params.IdentityProvider{
			Name:     "provider1",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		},
		status: http.StatusUnauthorized,
		result: params.Error{
			Message: `invalid credentials`,
			Code:    params.ErrUnauthorized,
		},
	}, {
		about:    "no provider name",
		username: adminUsername,
		password: adminPassword,
		idp: params.IdentityProvider{
			Name:     "",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		},
		status: http.StatusBadRequest,
		result: params.Error{
			Message: `No name for identity provider`,
			Code:    params.ErrBadRequest,
		},
	}, {
		about:    "no login url",
		username: adminUsername,
		password: adminPassword,
		idp: params.IdentityProvider{
			Name:     "provider1",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{},
		},
		status: http.StatusBadRequest,
		result: params.Error{
			Message: `openid.login_url not specified`,
			Code:    params.ErrBadRequest,
		},
	}, {
		about:    "login url wrong type",
		username: adminUsername,
		password: adminPassword,
		idp: params.IdentityProvider{
			Name:     "provider1",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: 43.4,
			},
		},
		status: http.StatusBadRequest,
		result: params.Error{
			Message: `openid.login_url not specified`,
			Code:    params.ErrBadRequest,
		},
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler: s.srv,
			Method:  "PUT",
			URL:     "/" + version + "/idps/",
			Body:    marshal(c, test.idp),
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			Username:     test.username,
			Password:     test.password,
			ExpectStatus: test.status,
			ExpectBody:   test.result,
		})
	}
}

func (s *apiSuite) TestGetIDPS(c *gc.C) {
	provider1 := &mongodoc.IdentityProvider{
		Name:     "provider1",
		Protocol: params.ProtocolOpenID20,
		LoginURL: "https://login.example.com",
	}
	err := s.store.SetIdentityProvider(provider1)
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
			Message: `cannot find identity provider "provider2"`,
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

func (s *apiSuite) TestListIDPS(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:    s.srv,
		Method:     "GET",
		URL:        fmt.Sprintf("/%s/idps/", version),
		ExpectBody: []string{},
	})
	err := s.store.SetIdentityProvider(
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
		URL:        fmt.Sprintf("/%s/idps/", version),
		ExpectBody: []string{"idp1"},
	})
	err = s.store.SetIdentityProvider(
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
		URL:        fmt.Sprintf("/%s/idps/", version),
		ExpectBody: []string{"idp1", "idp2"},
	})
}

func (s *apiSuite) TestPostIDPS(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		Method:  "POST",
		URL:     fmt.Sprintf("/%s/idps/", version),
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusBadRequest,
		ExpectBody: params.Error{
			Message: `unsupported method "POST"`,
			Code:    params.ErrBadRequest,
		},
	})
}

// marshal converts a value into a bytes.Reader containing the json
// encoding of that value.
func marshal(c *gc.C, v interface{}) *bytes.Reader {
	b, err := json.Marshal(v)
	c.Assert(err, gc.Equals, nil)
	return bytes.NewReader(b)
}
