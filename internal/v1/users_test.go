// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"net/http"
	"strings"

	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

type usersSuite struct {
	apiSuite
}

var _ = gc.Suite(&usersSuite{})

func (s *usersSuite) TestCreateUser(c *gc.C) {
	s.createIdentityProvider(c)
	s.createUser(c, "jbloggs2")
	tests := []struct {
		about        string
		method       string
		body         interface{}
		expectStatus int
		expectBody   interface{}
	}{{
		about:  "create user",
		method: "POST",
		body: params.User{
			UserName:         "jbloggs",
			IdentityProvider: "usso",
		},
		expectStatus: http.StatusOK,
		expectBody: params.User{
			UserName:         "jbloggs",
			IdentityProvider: "usso",
		},
	}, {
		about:  "create existing user",
		method: "POST",
		body: params.User{
			UserName:         "jbloggs2",
			IdentityProvider: "usso",
		},
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Code:    "bad request",
			Message: "bad request: already exists",
		},
	}, {
		about:  "unsupported method",
		method: "GET",
		body: params.User{
			UserName:         "jbloggs",
			IdentityProvider: "usso",
		},
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Code:    "bad request",
			Message: "unsupported method \"GET\"",
		},
	}, {
		about:  "no userid",
		method: "POST",
		body: params.User{
			UserName:         "",
			IdentityProvider: "usso",
		},
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Code:    "bad request",
			Message: "no userid",
		},
	}, {
		about:  "no idp",
		method: "POST",
		body: params.User{
			UserName:         "jbloggs",
			IdentityProvider: "",
		},
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Code:    "bad request",
			Message: "no identity provider",
		},
	}, {
		about:  "unsupported idp",
		method: "POST",
		body: params.User{
			UserName:         "jbloggs",
			IdentityProvider: "unsupported",
		},
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Code:    "bad request",
			Message: "unsupported identity provider \"unsupported\"",
		},
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler: s.srv,
			URL:     apiURL("u"),
			Method:  test.method,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			Body:         marshal(c, test.body),
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectBody,
		})
	}
}

func (s *usersSuite) TestCreateUserWritesToDatabase(c *gc.C) {
	s.createIdentityProvider(c)
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u"),
		Method:  "POST",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: marshal(c, params.User{
			UserName:         "jbloggs",
			IdentityProvider: "usso",
		}),
		ExpectStatus: http.StatusOK,
		ExpectBody: params.User{
			UserName:         "jbloggs",
			IdentityProvider: "usso",
		},
	})
	var doc mongodoc.Identity
	err := s.store.DB.Identities().Find(nil).One(&doc)
	c.Assert(err, gc.IsNil)
	c.Assert(doc.UserName, gc.Equals, "jbloggs")
	c.Assert(doc.IdentityProvider, gc.Equals, "usso")
}

func (s *usersSuite) TestCreateUserBadJSON(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u"),
		Method:  "POST",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:         strings.NewReader("invalid"),
		ExpectStatus: http.StatusBadRequest,
		ExpectBody: params.Error{
			Code:    "bad request",
			Message: "invalid JSON data: invalid character 'i' looking for beginning of value",
		},
	})
}

func (s *usersSuite) TestUser(c *gc.C) {
	s.createIdentityProvider(c)
	s.createUser(c, "jbloggs")
	tests := []struct {
		about        string
		url          string
		method       string
		expectStatus int
		expectBody   interface{}
	}{{
		about:        "known user",
		url:          apiURL("u/jbloggs"),
		method:       "GET",
		expectStatus: http.StatusOK,
		expectBody: params.User{
			UserName:         "jbloggs",
			IdentityProvider: "usso",
		},
	}, {
		about:        "unknown user",
		url:          apiURL("u/jbloggs2"),
		method:       "GET",
		expectStatus: http.StatusNotFound,
		expectBody: params.Error{
			Code:    "not found",
			Message: `user "jbloggs2" not found: not found`,
		},
	}, {
		about:        "unsupported method",
		url:          apiURL("u/jbloggs"),
		method:       "POST",
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Code:    "bad request",
			Message: "unsupported method \"POST\"",
		},
	}, {
		about:        "no username",
		url:          apiURL("u/"),
		method:       "GET",
		expectStatus: http.StatusNotFound,
		expectBody: params.Error{
			Code:    "not found",
			Message: `user "" not found: not found`,
		},
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler: s.srv,
			URL:     test.url,
			Method:  test.method,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectBody,
		})
	}
}

func (s *usersSuite) createIdentityProvider(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("idps/"),
		Method:  "PUT",
		Body: marshal(c, params.IdentityProvider{
			Name:     "usso",
			Protocol: params.ProtocolOpenID20,
			Settings: map[string]interface{}{
				params.OpenID20LoginURL: "https://login.example.com",
			},
		}),
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
		ExpectBody:   true,
	})
}

func (s *usersSuite) createUser(c *gc.C, name string) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u"),
		Method:  "POST",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: marshal(c, params.User{
			UserName:         name,
			IdentityProvider: "usso",
		}),
		ExpectStatus: http.StatusOK,
		ExpectBody: params.User{
			UserName:         name,
			IdentityProvider: "usso",
		},
	})
}
