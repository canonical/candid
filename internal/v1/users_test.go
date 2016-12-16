// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/juju/idmclient/params"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/internal/v1"
)

type usersSuite struct {
	apiSuite
}

var _ = gc.Suite(&usersSuite{})

func (s *usersSuite) TestUser(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.createUser(c, &params.User{
		Username:   "jbloggs2",
		ExternalID: "http://example.com/jbloggs2",
		Email:      "jbloggs2@example.com",
		FullName:   "Joe Bloggs II",
		IDPGroups: []string{
			"test",
		},
	})
	s.createUser(c, &params.User{
		Username:   "jbloggs3",
		ExternalID: "http://example.com/jbloggs3",
		Email:      "jbloggs3@example.com",
		FullName:   "Joe Bloggs III",
		IDPGroups: []string{
			"test",
		},
	})
	s.createUser(c, &params.User{
		Username: "agent@" + store.AdminUsername,
		IDPGroups: []string{
			"test",
		},
		Owner: store.AdminUsername,
		PublicKeys: []*bakery.PublicKey{
			&key.Public,
		},
	})
	s.createUser(c, &params.User{
		Username:   "jbloggs7",
		ExternalID: "http://example.com/jbloggs7",
		Email:      "jbloggs7@example.com",
		FullName:   "Joe Bloggs VII",
		IDPGroups: []string{
			"test",
			"test2",
			"test2",
		},
	})
	tests := []struct {
		about        string
		url          string
		method       string
		body         io.Reader
		header       http.Header
		username     string
		password     string
		expectStatus int
		expectBody   interface{}
	}{{
		about:  "create user",
		url:    apiURL("u/jbloggs"),
		method: "PUT",
		body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
	}, {
		about:  "reuse external_id",
		url:    apiURL("u/jbloggs5"),
		method: "PUT",
		body: marshal(c, params.User{
			Username:   "jbloggs5",
			ExternalID: "http://example.com/jbloggs2",
			Email:      "jbloggs5@example.com",
			FullName:   "Joe Bloggs V",
			IDPGroups: []string{
				"test",
			},
		}),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusForbidden,
		expectBody: params.Error{
			Code:    "already exists",
			Message: `cannot add user: duplicate username or external_id`,
		},
	}, {
		about:        "known user",
		url:          apiURL("u/jbloggs3"),
		method:       "GET",
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody: params.User{
			Username:   "jbloggs3",
			ExternalID: "http://example.com/jbloggs3",
			Email:      "jbloggs3@example.com",
			FullName:   "Joe Bloggs III",
			GravatarID: "21e89fe03e3a3cc553933f99eb442d94",
			IDPGroups: []string{
				"test",
			},
		},
	}, {
		about:        "unknown user",
		url:          apiURL("u/jbloggs4"),
		method:       "GET",
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusNotFound,
		expectBody: params.Error{
			Code:    "not found",
			Message: `user "jbloggs4" not found: not found`,
		},
	}, {
		about:        "get no username",
		url:          apiURL("u/"),
		method:       "GET",
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusNotFound,
		expectBody: params.Error{
			Code:    params.ErrNotFound,
			Message: `not found: /v1/u/`,
		},
	}, {
		about:    "unsupported method",
		url:      apiURL("u/jbloggs"),
		method:   "POST",
		username: adminUsername,
		password: adminPassword,
		body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		expectStatus: http.StatusMethodNotAllowed,
		expectBody: params.Error{
			Code:    params.ErrMethodNotAllowed,
			Message: "POST not allowed for /v1/u/jbloggs",
		},
	}, {
		about:    "put no userid",
		url:      apiURL("u/"),
		method:   "PUT",
		username: adminUsername,
		password: adminPassword,
		body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		expectStatus: http.StatusNotFound,
		expectBody: params.Error{
			Code:    "not found",
			Message: "not found: /v1/u/",
		},
	}, {
		about:    "put userid mismatch",
		url:      apiURL("u/jbloggs6"),
		method:   "PUT",
		username: adminUsername,
		password: adminPassword,
		body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs6",
			Email:      "jbloggs6@example.com",
			FullName:   "Joe Bloggs VI",
			IDPGroups: []string{
				"test6",
			},
		}),
		expectStatus: http.StatusOK,
	}, {
		about:        "bad json",
		url:          apiURL("u/jbloggs2"),
		method:       "PUT",
		username:     adminUsername,
		password:     adminPassword,
		body:         strings.NewReader("invalid"),
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Code:    "bad request",
			Message: "cannot unmarshal parameters: cannot unmarshal into field: cannot unmarshal request body: invalid character 'i' looking for beginning of value",
		},
	}, {
		about:    "incorrect username",
		url:      apiURL("u/jbloggs2"),
		method:   "PUT",
		username: "bad user",
		password: adminPassword,
		body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		expectStatus: http.StatusUnauthorized,
		expectBody: params.Error{
			Code:    "unauthorized",
			Message: "invalid credentials",
		},
	}, {
		about:    "incorrect password",
		url:      apiURL("u/jbloggs2"),
		method:   "PUT",
		username: adminUsername,
		password: "bad password",
		body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		expectStatus: http.StatusUnauthorized,
		expectBody: params.Error{
			Code:    "unauthorized",
			Message: "invalid credentials",
		},
	}, {
		about:  "no credentials",
		url:    apiURL("u/jbloggs2"),
		method: "PUT",
		body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		expectStatus: http.StatusProxyAuthRequired,
		expectBody:   DischargeRequiredBody,
	}, {
		about:  "no credentials and new bakery protocol",
		url:    apiURL("u/jbloggs2"),
		method: "PUT",
		body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		header:       map[string][]string{"Bakery-Protocol-Version": {"1"}},
		expectStatus: http.StatusUnauthorized,
		expectBody:   DischargeRequiredBody,
	}, {
		about:  "bad username",
		url:    apiURL("u/jbloggs{}"),
		method: "PUT",
		body: marshal(c, params.User{
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Code:    "bad request",
			Message: `cannot unmarshal parameters: cannot unmarshal into field: illegal username "jbloggs{}"`,
		},
	}, {
		about:  "long username",
		url:    apiURL("u/jbloggs001jbloggs002jbloggs003jbloggs004jbloggs005jbloggs006jbloggs007jbloggs008jbloggs009jbloggs010jbloggs011jbloggs012jbloggs013jbloggs014jbloggs015jbloggs016jbloggs017jbloggs018jbloggs019jbloggs020jbloggs021jbloggs022jbloggs023jbloggs024jbloggs025jbloggs026"),
		method: "PUT",
		body: marshal(c, params.User{
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Code:    "bad request",
			Message: `cannot unmarshal parameters: cannot unmarshal into field: username longer than 256 characters`,
		},
	}, {
		about:  "invalid subpath",
		url:    apiURL("u/jbloggs2/notthere"),
		method: "GET",
		body: marshal(c, params.User{
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusNotFound,
		expectBody: params.Error{
			Code:    "not found",
			Message: `not found: /v1/u/jbloggs2/notthere`,
		},
	}, {
		about:  "put agent user",
		url:    apiURL("u/agent2@" + store.AdminUsername),
		method: "PUT",
		body: marshal(c, params.User{
			IDPGroups: []string{
				"test",
			},
			Owner: params.Username(store.AdminUsername),
			PublicKeys: []*bakery.PublicKey{
				&key.Public,
			},
		}),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
	}, {
		about:        "get agent user",
		url:          apiURL("u/agent@" + store.AdminUsername),
		method:       "GET",
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody: params.User{
			Username: "agent@" + store.AdminUsername,
			IDPGroups: []string{
				"test",
			},
			Owner: store.AdminUsername,
			PublicKeys: []*bakery.PublicKey{
				&key.Public,
			},
		},
	}, {
		about:  "reserved username",
		url:    apiURL("u/everyone"),
		method: "PUT",
		body: marshal(c, params.User{
			ExternalID: "http://example.com/jbloggs8",
			Email:      "jbloggs8@example.com",
			FullName:   "Joe Bloggs VIII",
			IDPGroups: []string{
				"test",
			},
		}),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusForbidden,
		expectBody: params.Error{
			Code:    "forbidden",
			Message: `username "everyone" is reserved`,
		},
	}, {
		about:  "no external_id",
		url:    apiURL("u/jbloggs8"),
		method: "PUT",
		body: marshal(c, params.User{
			Email:    "jbloggs8@example.com",
			FullName: "Joe Bloggs VIII",
			IDPGroups: []string{
				"test",
			},
		}),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusBadRequest,
		expectBody: params.Error{
			Code:    params.ErrBadRequest,
			Message: `external_id not specified`,
		},
	}, {
		about:  "agent no credentials",
		url:    apiURL("u/agent@admin@idm"),
		method: "PUT",
		body: marshal(c, params.User{
			Owner: params.Username("admin@idm"),
			IDPGroups: []string{
				"test",
			},
		}),
		expectStatus: http.StatusProxyAuthRequired,
		expectBody:   DischargeRequiredBody,
	}, {
		about:  "agent bad username",
		url:    apiURL("u/agent@admin@idm@bad"),
		method: "PUT",
		body: marshal(c, params.User{
			Owner: params.Username("admin@idm"),
			IDPGroups: []string{
				"test",
			},
		}),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusForbidden,
		expectBody: params.Error{
			Code:    params.ErrForbidden,
			Message: `admin@idm cannot create user "agent@admin@idm@bad" (suffix must be "@admin@idm")`,
		},
	}, {
		about:        "user with duplicate groups",
		url:          apiURL("u/jbloggs7"),
		method:       "GET",
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody: params.User{
			Username:   "jbloggs7",
			ExternalID: "http://example.com/jbloggs7",
			Email:      "jbloggs7@example.com",
			FullName:   "Joe Bloggs VII",
			GravatarID: "4b5b372b2f8dde66ad32d3c63c1894b2",
			IDPGroups: []string{
				"test",
				"test2",
			},
		},
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		httpHeader := http.Header{
			"Content-Type": []string{"application/json"},
		}
		for key, value := range test.header {
			httpHeader[key] = value
		}
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:      s.srv,
			URL:          test.url,
			Method:       test.method,
			Header:       httpHeader,
			Body:         test.body,
			Username:     test.username,
			Password:     test.password,
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectBody,
		})
	}
}

func (s *usersSuite) TestSetUserMergesGroups(c *gc.C) {
	s.createUser(c, &params.User{
		Username:   "jbloggs2",
		ExternalID: "http://example.com/jbloggs2",
		Email:      "jbloggs2@example.com",
		FullName:   "Joe Bloggs II",
		IDPGroups: []string{
			"test",
		},
	})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/jbloggs2"),
		Method:  "PUT",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: marshal(c, params.User{
			Username:   "jbloggs2",
			ExternalID: "http://example.com/jbloggs2",
			Email:      "jbloggs2@example.com",
			FullName:   "Joe Bloggs II",
			IDPGroups: []string{
				"test2",
			},
		}),
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
	})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/jbloggs2"),
		Method:  "GET",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
		ExpectBody: params.User{
			Username:   "jbloggs2",
			ExternalID: "http://example.com/jbloggs2",
			Email:      "jbloggs2@example.com",
			FullName:   "Joe Bloggs II",
			GravatarID: "b1337cf8d58e2e2be9b6a5356cfc268b",
			IDPGroups: []string{
				"test",
				"test2",
			},
		},
	})
}

func (s *usersSuite) TestSetAgentOverwritesGroups(c *gc.C) {
	s.createUser(c, &params.User{
		Username: "agent@admin@idm",
		Owner:    "admin@idm",
		IDPGroups: []string{
			"test",
		},
	})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/agent@admin@idm"),
		Method:  "PUT",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: marshal(c, params.User{
			Username: "agent@admin@idm",
			Owner:    "admin@idm",
			IDPGroups: []string{
				"test2",
			},
		}),
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
	})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/agent@admin@idm"),
		Method:  "GET",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
		ExpectBody: params.User{
			Username: "agent@admin@idm",
			Owner:    "admin@idm",
			IDPGroups: []string{
				"test2",
			},
		},
	})
}

func (s *usersSuite) TestGetUserGetsGroupsFromLaunchpad(c *gc.C) {

	s.PatchValue(v1.StoreGetLaunchpadGroups, func(s *store.Store, externalId string) ([]string, error) {
		return []string{"test3"}, nil
	})

	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/jbloggs2"),
		Method:  "PUT",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: marshal(c, params.User{
			Username:   "jbloggs2",
			ExternalID: "https://login.ubuntu.com/+id/test",
			Email:      "jbloggs2@example.com",
			FullName:   "Joe Bloggs II",
			IDPGroups: []string{
				"test",
				"test2",
			},
		}),
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
	})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/jbloggs2"),
		Method:  "GET",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
		ExpectBody: params.User{
			Username:   "jbloggs2",
			ExternalID: "https://login.ubuntu.com/+id/test",
			Email:      "jbloggs2@example.com",
			FullName:   "Joe Bloggs II",
			GravatarID: "b1337cf8d58e2e2be9b6a5356cfc268b",
			IDPGroups: []string{
				"test",
				"test2",
				"test3",
			},
		},
	})
}

func (s *usersSuite) TestUpdateAgentSetPublicKeys(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.createUser(c, &params.User{
		Username: "agent@" + store.AdminUsername,
		Owner:    store.AdminUsername,
		PublicKeys: []*bakery.PublicKey{
			&key.Public,
		},
	})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/agent@" + store.AdminUsername),
		Method:  "GET",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
		ExpectBody: params.User{
			Username:  "agent@" + store.AdminUsername,
			Owner:     store.AdminUsername,
			IDPGroups: []string{},
			PublicKeys: []*bakery.PublicKey{
				&key.Public,
			},
		},
	})
	key, err = bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/agent@" + store.AdminUsername),
		Method:  "PUT",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: marshal(c, params.User{
			Username: "agent@" + store.AdminUsername,
			Owner:    store.AdminUsername,
			PublicKeys: []*bakery.PublicKey{
				&key.Public,
			},
			IDPGroups: []string{},
		}),
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
	})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/agent@" + store.AdminUsername),
		Method:  "GET",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
		ExpectBody: params.User{
			Username: "agent@" + store.AdminUsername,
			Owner:    store.AdminUsername,
			PublicKeys: []*bakery.PublicKey{
				&key.Public,
			},
			IDPGroups: []string{},
		},
	})
}

func (s *usersSuite) TestCreateUserWritesToDatabase(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/jbloggs"),
		Method:  "PUT",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
	})
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	var doc mongodoc.Identity
	err := store.DB.Identities().Find(bson.D{{"username", "jbloggs"}}).One(&doc)
	c.Assert(err, gc.IsNil)
	c.Assert(doc.Username, gc.Equals, "jbloggs")
	c.Assert(doc.ExternalID, gc.Equals, "http://example.com/jbloggs")
	c.Assert(doc.Email, gc.Equals, "jbloggs@example.com")
	c.Assert(doc.FullName, gc.Equals, "Joe Bloggs")
	c.Assert(doc.Groups, gc.DeepEquals, []string{"test"})
}

func (s *usersSuite) TestQueryUsers(c *gc.C) {
	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)
	s.createUser(c, &params.User{
		Username:   "jbloggs2",
		ExternalID: "http://example.com/jbloggs2",
		Email:      "jbloggs2@example.com",
		FullName:   "Joe Bloggs II",
		IDPGroups: []string{
			"test",
		},
	})
	st.UpdateIdentity("jbloggs2", bson.D{{"$set", bson.D{{"lastlogin", time.Now().AddDate(0, 0, -29)}}}})
	st.UpdateIdentity("jbloggs2", bson.D{{"$set", bson.D{{"lastdischarge", time.Now().AddDate(0, 0, -14)}}}})
	tests := []struct {
		about        string
		url          string
		method       string
		body         io.Reader
		username     string
		password     string
		expectStatus int
		expectBody   interface{}
	}{{
		about:        "query existing user",
		url:          apiURL("u?external_id=http://example.com/jbloggs2"),
		method:       "GET",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{"jbloggs2"},
	}, {
		about:        "query non-existing user",
		url:          apiURL("u?external_id=http://example.com/jbloggs"),
		method:       "GET",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{},
	}, {
		about:        "no query parameter",
		url:          apiURL("u"),
		method:       "GET",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{store.AdminUsername, "jbloggs2"},
	}, {
		about:        "incorrect method",
		url:          apiURL("u?external_id=http://example.com/jbloggs"),
		method:       "DELETE",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusMethodNotAllowed,
		expectBody: params.Error{
			Code:    params.ErrMethodNotAllowed,
			Message: "DELETE not allowed for /v1/u",
		},
	}, {
		about:    "incorrect username",
		url:      apiURL("u?external_id=http://example.com/jbloggs2"),
		method:   "GET",
		username: "bad user",
		password: adminPassword,
		body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		expectStatus: http.StatusUnauthorized,
		expectBody: params.Error{
			Code:    "unauthorized",
			Message: "invalid credentials",
		},
	}, {
		about:    "incorrect password",
		url:      apiURL("u?external_id=http://example.com/jbloggs2"),
		method:   "GET",
		username: adminUsername,
		password: "bad password",
		body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		expectStatus: http.StatusUnauthorized,
		expectBody: params.Error{
			Code:    "unauthorized",
			Message: "invalid credentials",
		},
	}, {
		about:  "no credentials",
		url:    apiURL("u?external_id=http://example.com/jbloggs2"),
		method: "GET",
		body: marshal(c, params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		}),
		expectStatus: http.StatusProxyAuthRequired,
		expectBody:   DischargeRequiredBody,
	}, {
		about:        "query email",
		url:          apiURL("u?email=jbloggs2@example.com"),
		method:       "GET",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{"jbloggs2"},
	}, {
		about:        "query email not found",
		url:          apiURL("u?email=not-there@example.com"),
		method:       "GET",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{},
	}, {
		about:        "last login in range",
		url:          apiURL("u?last-login-since=" + url.QueryEscape(time.Now().AddDate(0, 0, -30).Format(time.RFC3339))),
		method:       "GET",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{"jbloggs2"},
	}, {
		about:        "last login too soon",
		url:          apiURL("u?last-login-since=" + url.QueryEscape(time.Now().AddDate(0, 0, -28).Format(time.RFC3339))),
		method:       "GET",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{},
	}, {
		about:        "last discharge in range",
		url:          apiURL("u?last-discharge-since=" + url.QueryEscape(time.Now().AddDate(0, 0, -15).Format(time.RFC3339))),
		method:       "GET",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{"jbloggs2"},
	}, {
		about:        "last discharge too soon",
		url:          apiURL("u?last-discharge-since=" + url.QueryEscape(time.Now().AddDate(0, 0, -13).Format(time.RFC3339))),
		method:       "GET",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{},
	}, {
		about:        "combined login and discharge (found)",
		url:          apiURL("u?last-discharge-since=" + url.QueryEscape(time.Now().AddDate(0, 0, -15).Format(time.RFC3339)) + "&last-login-since=" + url.QueryEscape(time.Now().AddDate(0, 0, -30).Format(time.RFC3339))),
		method:       "GET",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{"jbloggs2"},
	}, {
		about:        "combined login and discharge (not found)",
		url:          apiURL("u?last-discharge-since=" + url.QueryEscape(time.Now().AddDate(0, 0, -13).Format(time.RFC3339)) + "&last-login-since=" + url.QueryEscape(time.Now().AddDate(0, 0, -30).Format(time.RFC3339))),
		method:       "GET",
		body:         nil,
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{},
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
			Body:         test.body,
			Username:     test.username,
			Password:     test.password,
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectBody,
		})
	}
}

func (s *usersSuite) TestUserToken(c *gc.C) {
	s.createUser(c, &params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
		Email:      "jbloggs@example.com",
		FullName:   "Joe Bloggs",
		IDPGroups: []string{
			"test",
		},
	})
	tests := []struct {
		about         string
		url           string
		username      string
		password      string
		checkResponse func(*gc.C, *httptest.ResponseRecorder)
	}{{
		about:    "get user token",
		url:      apiURL("u/jbloggs/macaroon"),
		username: adminUsername,
		password: adminPassword,
		checkResponse: func(c *gc.C, resp *httptest.ResponseRecorder) {
			c.Assert(resp.Code, gc.Equals, http.StatusOK)
			var m macaroon.Macaroon
			err := json.Unmarshal(resp.Body.Bytes(), &m)
			c.Assert(err, gc.IsNil)
			s.assertMacaroon(c, macaroon.Slice{&m}, "jbloggs")
		},
	}, {
		about:    "no user",
		url:      apiURL("u/jbloggs2/macaroon"),
		username: adminUsername,
		password: adminPassword,
		checkResponse: func(c *gc.C, resp *httptest.ResponseRecorder) {
			c.Assert(resp.Code, gc.Equals, http.StatusNotFound)
			c.Assert(resp.Body.String(), jc.JSONEquals, params.Error{
				Code:    "not found",
				Message: `user "jbloggs2" not found: not found`,
			})
		},
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		resp := httptesting.DoRequest(c, httptesting.DoRequestParams{
			Handler:  s.srv,
			URL:      test.url,
			Method:   "GET",
			Username: test.username,
			Password: test.password,
		})
		test.checkResponse(c, resp)
	}
}

func (s *usersSuite) TestSSHKeys(c *gc.C) {
	s.createUser(c, &params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
		Email:      "jbloggs@example.com",
		FullName:   "Joe Bloggs",
		IDPGroups: []string{
			"test",
		},
	})
	// Check there is no ssh key for the user.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:  s.srv,
		URL:      apiURL("u/jbloggs/ssh-keys"),
		Method:   "GET",
		Username: adminUsername,
		Password: adminPassword,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		ExpectStatus: http.StatusOK,
		ExpectBody:   params.SSHKeysResponse{},
	})
	// Add ssh keys to the user.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/jbloggs/ssh-keys"),
		Method:  "PUT",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Username: adminUsername,
		Password: adminPassword,
		Body: marshal(c, params.PutSSHKeysBody{
			SSHKeys: []string{"36ASDER56", "22ERT56DG", "56ASDFASDF32"},
			Add:     false,
		}),
		ExpectStatus: http.StatusOK,
	})
	// Check it is present.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/jbloggs/ssh-keys"),
		Method:  "GET",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
		ExpectBody: params.SSHKeysResponse{
			SSHKeys: []string{
				"36ASDER56",
				"22ERT56DG",
				"56ASDFASDF32",
			},
		},
	})
	// Remove some ssh keys.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:  s.srv,
		URL:      apiURL("u/jbloggs/ssh-keys"),
		Method:   "DELETE",
		Username: adminUsername,
		Password: adminPassword,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: marshal(c, params.DeleteSSHKeysBody{
			SSHKeys: []string{"22ERT56DG", "56ASDFASDF32"},
		}),
		ExpectStatus: http.StatusOK,
	})
	// Check we only get one.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:  s.srv,
		URL:      apiURL("u/jbloggs/ssh-keys"),
		Method:   "GET",
		Username: adminUsername,
		Password: adminPassword,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		ExpectStatus: http.StatusOK,
		ExpectBody: params.SSHKeysResponse{
			SSHKeys: []string{
				"36ASDER56",
			},
		},
	})
	// Delete an unknown ssh key just do nothing silently.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:  s.srv,
		URL:      apiURL("u/jbloggs/ssh-keys"),
		Method:   "DELETE",
		Username: adminUsername,
		Password: adminPassword,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: marshal(c, params.DeleteSSHKeysBody{
			[]string{"22ERT56DG"},
		}),
		ExpectStatus: http.StatusOK,
	})
	// Check we only get one.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:  s.srv,
		URL:      apiURL("u/jbloggs/ssh-keys"),
		Method:   "GET",
		Username: adminUsername,
		Password: adminPassword,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		ExpectStatus: http.StatusOK,
		ExpectBody: params.SSHKeysResponse{
			SSHKeys: []string{
				"36ASDER56",
			},
		},
	})
	// Append one ssh key.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/jbloggs/ssh-keys"),
		Method:  "PUT",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Username: adminUsername,
		Password: adminPassword,
		Body: marshal(c, params.PutSSHKeysBody{
			SSHKeys: []string{"90SDFGS45"},
			Add:     true,
		}),
		ExpectStatus: http.StatusOK,
	})
	// Check we get two.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:  s.srv,
		URL:      apiURL("u/jbloggs/ssh-keys"),
		Method:   "GET",
		Username: adminUsername,
		Password: adminPassword,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		ExpectStatus: http.StatusOK,
		ExpectBody: params.SSHKeysResponse{
			SSHKeys: []string{
				"36ASDER56",
				"90SDFGS45",
			},
		},
	})
}

func (s *usersSuite) TestVerifyUserToken(c *gc.C) {
	s.createUser(c, &params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
		Email:      "jbloggs@example.com",
		FullName:   "Joe Bloggs",
		IDPGroups: []string{
			"test",
		},
	})
	m := s.getToken(c, "jbloggs")
	badm, err := macaroon.New([]byte{}, []byte("no such macaroon"), "loc", macaroon.LatestVersion)
	c.Assert(err, gc.IsNil)
	tests := []struct {
		about        string
		body         io.Reader
		expectStatus int
		expectBody   interface{}
	}{{
		about:        "verify token",
		body:         marshal(c, macaroon.Slice{m}),
		expectStatus: http.StatusOK,
		expectBody: map[string]string{
			"username": "jbloggs",
		},
	}, {
		about:        "bad token",
		body:         marshal(c, macaroon.Slice{badm}),
		expectStatus: http.StatusForbidden,
		expectBody: params.Error{
			Code:    "forbidden",
			Message: "verification failure: macaroon discharge required: authentication required",
		},
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler: s.srv,
			URL:     apiURL("verify"),
			Method:  "POST",
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			Body:         test.body,
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectBody,
		})
	}
}

func (s *usersSuite) TestUserIDPGroups(c *gc.C) {
	s.createUser(c, &params.User{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		IDPGroups:  []string{},
	})
	s.createUser(c, &params.User{
		Username:   "test2",
		ExternalID: "http://example.com/test2",
		Email:      "test2@example.com",
		FullName:   "Test User II",
		IDPGroups: []string{
			"test",
		},
	})
	s.createUser(c, &params.User{
		Username:   "test3",
		ExternalID: "http://example.com/test3",
		Email:      "test3@example.com",
		FullName:   "Test User III",
		IDPGroups: []string{
			"test",
			"test2",
		},
	})
	s.createUser(c, &params.User{
		Username:   "test5",
		ExternalID: "http://example.com/test5",
		Email:      "test5@example.com",
		FullName:   "Test User V",
		IDPGroups: []string{
			"test",
			"test2",
			"test2",
		},
	})
	tests := []struct {
		about        string
		url          string
		username     string
		password     string
		expectStatus int
		expectBody   interface{}
	}{{
		about:        "user without groups",
		url:          apiURL("u/test/idpgroups"),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{},
	}, {
		about:        "user with 1 group",
		url:          apiURL("u/test2/idpgroups"),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{"test"},
	}, {
		about:        "user with 2 groups",
		url:          apiURL("u/test3/idpgroups"),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{"test", "test2"},
	}, {
		about:        "unknown user",
		url:          apiURL("u/test4/idpgroups"),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusNotFound,
		expectBody: params.Error{
			Code:    "not found",
			Message: `user "test4" not found: not found`,
		},
	}, {
		about:        "user with duplicate group",
		url:          apiURL("u/test5/idpgroups"),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusOK,
		expectBody:   []string{"test", "test2"},
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:      s.srv,
			URL:          test.url,
			Username:     test.username,
			Password:     test.password,
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectBody,
		})
	}
}

func (s *usersSuite) TestUserGroups(c *gc.C) {
	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)
	s.createUser(c, &params.User{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		IDPGroups:  []string{},
	})
	s.createUser(c, &params.User{
		Username:   "test2",
		ExternalID: "http://example.com/test2",
		Email:      "test2@example.com",
		FullName:   "Test User II",
		IDPGroups: []string{
			"test",
		},
	})
	s.createUser(c, &params.User{
		Username:   "test3",
		ExternalID: "http://example.com/test3",
		Email:      "test3@example.com",
		FullName:   "Test User III",
		IDPGroups: []string{
			"test",
			"test2",
		},
	})
	s.createUser(c, &params.User{
		Username:   "grouplister",
		ExternalID: "http://example.com/grouplister",
		Email:      "grouplister@example.com",
		FullName:   "Group Lister",
		IDPGroups: []string{
			store.GroupListGroup,
		},
	})
	s.createUser(c, &params.User{
		Username:   "test5",
		ExternalID: "http://example.com/test5",
		Email:      "test5@example.com",
		FullName:   "Test User V",
		IDPGroups: []string{
			"test",
			"test2",
			"test2",
		},
	})
	tests := []struct {
		about        string
		url          string
		username     string
		password     string
		expectStatus int
		expectBody   interface{}
	}{{
		about:        "user without groups",
		url:          apiURL("u/test/groups"),
		username:     "test",
		expectStatus: http.StatusOK,
		expectBody:   []string{},
	}, {
		about:        "user with 1 group",
		url:          apiURL("u/test2/groups"),
		username:     "test2",
		expectStatus: http.StatusOK,
		expectBody:   []string{"test"},
	}, {
		about:        "user with 2 groups",
		url:          apiURL("u/test3/groups"),
		username:     "test3",
		expectStatus: http.StatusOK,
		expectBody:   []string{"test", "test2"},
	}, {
		about:        "acl user",
		url:          apiURL("u/test2/groups"),
		username:     "grouplister",
		expectStatus: http.StatusOK,
		expectBody:   []string{"test"},
	}, {
		about:        "admin credentials",
		url:          apiURL("u/test4/groups"),
		username:     adminUsername,
		password:     adminPassword,
		expectStatus: http.StatusNotFound,
		expectBody: params.Error{
			Code:    "not found",
			Message: `user "test4" not found: not found`,
		},
	}, {
		about:        "discharge required",
		url:          apiURL("u/test/groups"),
		expectStatus: http.StatusProxyAuthRequired,
		expectBody:   DischargeRequiredBody,
	}, {
		about:        "user with duplicate group",
		url:          apiURL("u/test5/groups"),
		username:     "test5",
		expectStatus: http.StatusOK,
		expectBody:   []string{"test", "test2"},
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		var un string
		var cookies []*http.Cookie
		if test.password != "" {
			un = test.username
		} else if test.username != "" {
			cookies = cookiesForUser(st, test.username)
		}
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:      s.srv,
			URL:          test.url,
			Username:     un,
			Password:     test.password,
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectBody,
			Cookies:      cookies,
		})
	}
}

func (s *usersSuite) getToken(c *gc.C, un string) *macaroon.Macaroon {
	resp := httptesting.DoRequest(c, httptesting.DoRequestParams{
		Handler:  s.srv,
		URL:      apiURL("u/" + un + "/macaroon"),
		Method:   "GET",
		Username: adminUsername,
		Password: adminPassword,
	})
	var m macaroon.Macaroon
	err := json.Unmarshal(resp.Body.Bytes(), &m)
	c.Assert(err, gc.IsNil)
	return &m
}

var setUserGroupsTests = []struct {
	about        string
	username     string
	password     string
	startGroups  []string
	groups       []string
	expectStatus int
	expectError  interface{}
	expectGroups []string
}{{
	about:        "set groups",
	username:     adminUsername,
	password:     adminPassword,
	startGroups:  []string{"test1", "test2"},
	groups:       []string{"test3", "test4"},
	expectStatus: http.StatusOK,
	expectGroups: []string{"test3", "test4"},
}, {
	about:        "no permission",
	startGroups:  []string{"test1", "test2"},
	groups:       []string{"test3", "test4"},
	expectStatus: http.StatusForbidden,
	expectError: params.Error{
		Code:    params.ErrForbidden,
		Message: "user does not have correct permissions",
	},
	expectGroups: []string{"test1", "test2"},
}, {
	about:        "no user",
	username:     adminUsername,
	password:     adminPassword,
	startGroups:  nil,
	groups:       []string{"test3", "test4"},
	expectStatus: http.StatusNotFound,
	expectError: params.Error{
		Code:    params.ErrNotFound,
		Message: `user "test-2" not found: not found`,
	},
}}

func (s *usersSuite) TestSetUserGroups(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	for i, test := range setUserGroupsTests {
		c.Logf("test %d. %s", i, test.about)
		username := params.Username(fmt.Sprintf("test-%d", i))
		if test.startGroups != nil {
			s.createUser(c, &params.User{
				Username:   username,
				ExternalID: "http://example.com/" + string(username),
				IDPGroups:  test.startGroups,
			})
		}
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:      s.srv,
			Method:       "PUT",
			URL:          apiURL("u/" + string(username) + "/groups"),
			Username:     test.username,
			Password:     test.password,
			JSONBody:     params.Groups{Groups: test.groups},
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectError,
			Cookies:      cookiesForUser(store, test.username),
		})
		if test.expectError != nil {
			continue
		}
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:    s.srv,
			URL:        apiURL("u/" + string(username) + "/groups"),
			Username:   adminUsername,
			Password:   adminPassword,
			ExpectBody: test.expectGroups,
		})
	}
}

var modifyUserGroupsTests = []struct {
	about        string
	username     string
	password     string
	startGroups  []string
	addGroups    []string
	removeGroups []string
	expectStatus int
	expectError  interface{}
	expectGroups []string
}{{
	about:        "add groups",
	username:     adminUsername,
	password:     adminPassword,
	startGroups:  []string{"test1", "test2"},
	addGroups:    []string{"test3", "test4"},
	expectStatus: http.StatusOK,
	expectGroups: []string{"test1", "test2", "test3", "test4"},
}, {
	about:        "remove groups",
	username:     adminUsername,
	password:     adminPassword,
	startGroups:  []string{"test1", "test2"},
	removeGroups: []string{"test1", "test2"},
	expectStatus: http.StatusOK,
	expectGroups: []string{},
}, {
	about:        "add and remove groups",
	username:     adminUsername,
	password:     adminPassword,
	startGroups:  []string{"test1", "test2"},
	addGroups:    []string{"test3", "test4"},
	removeGroups: []string{"test1", "test2"},
	expectStatus: http.StatusBadRequest,
	expectError: params.Error{
		Code:    params.ErrBadRequest,
		Message: "cannot add and remove groups in the same operation",
	},
	expectGroups: []string{"test1", "test2"},
}, {
	about:        "remove groups not a member of",
	username:     adminUsername,
	password:     adminPassword,
	startGroups:  []string{"test1", "test2"},
	removeGroups: []string{"test5"},
	expectStatus: http.StatusOK,
	expectGroups: []string{"test1", "test2"},
}, {
	about:        "no permission",
	startGroups:  []string{"test1", "test2"},
	addGroups:    []string{"test3", "test4"},
	expectStatus: http.StatusForbidden,
	expectError: params.Error{
		Code:    params.ErrForbidden,
		Message: "user does not have correct permissions",
	},
	expectGroups: []string{"test1", "test2"},
}, {
	about:        "no user",
	username:     adminUsername,
	password:     adminPassword,
	startGroups:  nil,
	addGroups:    []string{"test3", "test4"},
	expectStatus: http.StatusNotFound,
	expectError: params.Error{
		Code:    params.ErrNotFound,
		Message: `user "test-5" not found: not found`,
	},
}, {
	about:        "no user, and no changes",
	username:     adminUsername,
	password:     adminPassword,
	startGroups:  nil,
	expectStatus: http.StatusNotFound,
	expectError: params.Error{
		Code:    params.ErrNotFound,
		Message: `user "test-6" not found: not found`,
	},
}}

func (s *usersSuite) TestModifyUserGroups(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	for i, test := range modifyUserGroupsTests {
		c.Logf("test %d. %s", i, test.about)
		username := params.Username(fmt.Sprintf("test-%d", i))
		if test.startGroups != nil {
			s.createUser(c, &params.User{
				Username:   username,
				ExternalID: "http://example.com/" + string(username),
				IDPGroups:  test.startGroups,
			})
		}
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:  s.srv,
			Method:   "POST",
			URL:      apiURL("u/" + string(username) + "/groups"),
			Username: test.username,
			Password: test.password,
			JSONBody: params.ModifyGroups{
				Add:    test.addGroups,
				Remove: test.removeGroups,
			},
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectError,
			Cookies:      cookiesForUser(store, test.username),
		})
		if test.expectError != nil {
			continue
		}
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:    s.srv,
			URL:        apiURL("u/" + string(username) + "/groups"),
			Username:   adminUsername,
			Password:   adminPassword,
			ExpectBody: test.expectGroups,
		})
	}
}

var extraInfoTests = []struct {
	about           string
	user            string
	item            string
	method          string
	body            interface{}
	expectStatus    int
	expectBody      interface{}
	expectExtraInfo map[string]interface{}
}{{
	about:        "get extra-info",
	user:         "jbloggs",
	method:       "GET",
	expectStatus: http.StatusOK,
	expectBody: map[string]interface{}{
		"item1": 1,
		"item2": "two",
	},
}, {
	about:  "set extra-info",
	user:   "jbloggs",
	method: "PUT",
	body: map[string]interface{}{
		"item1": 11,
		"item2": "twotwo",
	},
	expectStatus: http.StatusOK,
	expectExtraInfo: map[string]interface{}{
		"item1": 11,
		"item2": "twotwo",
	},
}, {
	about:  "set extra-info does not change unmentioned fields",
	user:   "jbloggs",
	method: "PUT",
	body: map[string]interface{}{
		"item3": 3,
		"item2": "twotwo",
	},
	expectStatus: http.StatusOK,
	expectExtraInfo: map[string]interface{}{
		"item1": 1,
		"item2": "twotwo",
		"item3": 3,
	},
}, {
	about:        "get extra-info item",
	user:         "jbloggs",
	item:         "item1",
	method:       "GET",
	expectStatus: http.StatusOK,
	expectBody:   1,
}, {
	about:        "set extra-info item",
	user:         "jbloggs",
	item:         "item1",
	method:       "PUT",
	body:         10.0,
	expectStatus: http.StatusOK,
	expectExtraInfo: map[string]interface{}{
		"item1": 10.0,
		"item2": "two",
	},
}, {
	about:        "get extra-info no user",
	user:         "jbloggs2",
	method:       "GET",
	expectStatus: http.StatusNotFound,
	expectBody: params.Error{
		Code:    params.ErrNotFound,
		Message: `user "jbloggs2" not found: not found`,
	},
}, {
	about:  "set extra-info no user",
	user:   "jbloggs2",
	method: "PUT",
	body: map[string]interface{}{
		"item1": 11,
		"item2": "twotwo",
	},
	expectStatus: http.StatusNotFound,
	expectBody: params.Error{
		Code:    params.ErrNotFound,
		Message: `user "jbloggs2" not found: not found`,
	},
}, {
	about:        "get extra-info item no user",
	user:         "jbloggs2",
	item:         "item1",
	method:       "GET",
	expectStatus: http.StatusNotFound,
	expectBody: params.Error{
		Code:    params.ErrNotFound,
		Message: `user "jbloggs2" not found: not found`,
	},
}, {
	about:        "set extra-info item no user",
	user:         "jbloggs2",
	item:         "item1",
	method:       "PUT",
	body:         10.0,
	expectStatus: http.StatusNotFound,
	expectBody: params.Error{
		Code:    params.ErrNotFound,
		Message: `user "jbloggs2" not found: not found`,
	},
}, {
	about:  "set extra-info when none present",
	user:   "jbloggs3",
	method: "PUT",
	body: map[string]interface{}{
		"item1": 11,
		"item2": "twotwo",
	},
	expectStatus: http.StatusOK,
	expectExtraInfo: map[string]interface{}{
		"item1": 11,
		"item2": "twotwo",
	},
}, {
	about:        "set extra-info item when none present",
	user:         "jbloggs3",
	item:         "item4",
	method:       "PUT",
	body:         4,
	expectStatus: http.StatusOK,
	expectExtraInfo: map[string]interface{}{
		"item4": 4,
	},
}, {
	about:  "set extra-info bad key",
	user:   "jbloggs3",
	method: "PUT",
	body: map[string]interface{}{
		"$item1": 1,
		"item2":  "twotwo",
	},
	expectStatus: http.StatusBadRequest,
	expectBody: params.Error{
		Code:    params.ErrBadRequest,
		Message: `"$item1" bad key for extra-info`,
	},
}, {
	about:        "set extra-info item bad key",
	user:         "jbloggs3",
	item:         "item.4",
	method:       "PUT",
	body:         4,
	expectStatus: http.StatusBadRequest,
	expectBody: params.Error{
		Code:    params.ErrBadRequest,
		Message: `"item.4" bad key for extra-info`,
	},
}}

func (s *usersSuite) TestExtraInfo(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	s.createUser(c, &params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
	})
	s.createUser(c, &params.User{
		Username:   "jbloggs3",
		ExternalID: "http://example.com/jbloggs3",
	})
	for i, test := range extraInfoTests {
		c.Logf("%d. %s", i, test.about)
		// Reset the stored extra-info for jbloggs
		err := store.UpdateIdentity("jbloggs", bson.D{{"$set", bson.D{{"extrainfo",
			map[string]json.RawMessage{
				"item1": json.RawMessage(`1`),
				"item2": json.RawMessage(`"two"`),
			},
		}}}})
		// Delete any stored extra-info for jbloggs3
		err = store.UpdateIdentity("jbloggs3", bson.D{{"$unset", bson.D{{"extrainfo", ""}}}})
		c.Assert(err, gc.IsNil)
		url := "u/" + test.user + "/extra-info"
		if test.item != "" {
			url += "/" + test.item
		}
		params := httptesting.JSONCallParams{
			Handler:  s.srv,
			URL:      apiURL(url),
			Method:   test.method,
			Username: adminUsername,
			Password: adminPassword,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectBody,
		}
		if test.body != nil {
			params.Body = marshal(c, test.body)
		}
		httptesting.AssertJSONCall(c, params)
		if test.expectExtraInfo != nil {
			httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
				Handler:      s.srv,
				URL:          apiURL("u/" + test.user + "/extra-info"),
				Method:       "GET",
				Username:     adminUsername,
				Password:     adminPassword,
				ExpectStatus: http.StatusOK,
				ExpectBody:   test.expectExtraInfo,
			})
		}
	}
}

func (s *usersSuite) TestMultipleEndpointAccess(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	s.createIdentity(c, &mongodoc.Identity{
		Username: "jbloggs1",
		Owner:    "test",
		Groups:   []string{"g1", "g2"},
	})
	s.createIdentity(c, &mongodoc.Identity{
		Username: "jbloggs2",
		Owner:    "test",
		Groups:   []string{"g3", "g4"},
	})
	client := httpbakery.NewClient()

	u, err := url.Parse(location)
	c.Assert(err, gc.IsNil)
	client.Client.Jar.SetCookies(u, cookiesForUser(store, "jbloggs1"))
	req, err := http.NewRequest("GET", location+"/v1/u/jbloggs1/groups", nil)
	c.Assert(err, gc.IsNil)
	resp, err := client.Do(req)
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, gc.IsNil)
	c.Assert(string(body), jc.JSONEquals, []string{"g1", "g2"})

	req, err = http.NewRequest("GET", location+"/v1/u/jbloggs2/groups", nil)
	c.Assert(err, gc.IsNil)
	resp, err = client.Do(req)
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusForbidden)
	body, err = ioutil.ReadAll(resp.Body)
	c.Assert(err, gc.IsNil)
	c.Assert(string(body), jc.JSONEquals, params.Error{
		Code:    params.ErrForbidden,
		Message: "user does not have correct permissions",
	})
}

func cookiesForUser(st *store.Store, username string) []*http.Cookie {
	if username == "" {
		return nil
	}
	m := macaroonForUser(st, username)
	cookie, err := httpbakery.NewCookie(st.Bakery.Checker.Namespace(), macaroon.Slice{m.M()})
	if err != nil {
		panic(err)
	}
	return []*http.Cookie{cookie}
}

func macaroonForUser(st *store.Store, username string) *bakery.Macaroon {
	m, err := st.Bakery.Oven.NewMacaroon(context.TODO(), bakery.LatestVersion, time.Now().Add(time.Minute), []checkers.Caveat{
		checkers.DeclaredCaveat("username", username),
	}, bakery.LoginOp)
	if err != nil {
		panic(err)
	}
	return m
}
