// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package test_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/qthttptest"
	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/candid/config"
	"github.com/CanonicalLtd/candid/idp"
	idptest "github.com/CanonicalLtd/candid/idp/qtidptest"
	"github.com/CanonicalLtd/candid/idp/test"
	candidtest "github.com/CanonicalLtd/candid/internal/qtcandidtest"
	"github.com/CanonicalLtd/candid/store"
)

func TestConfig(t *testing.T) {
	c := qt.New(t)
	configYaml := `
identity-providers:
 - type: test
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(configYaml), &conf)
	c.Assert(err, qt.Equals, nil)
	c.Assert(conf.IdentityProviders, qt.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), qt.Equals, "test")
}

type testSuite struct {
	idptest *idptest.Fixture
	idp     idp.IdentityProvider
	groups  []string
}

func (s *testSuite) Init(c *qt.C) {
	s.idptest = idptest.NewFixture(c, candidtest.NewStore())
	s.idp = test.NewIdentityProvider(test.Params{
		Name:      "test",
		GetGroups: s.getGroups,
	})
}

func (s *testSuite) getGroups(*store.Identity) ([]string, error) {
	return s.groups, nil
}

func (s *testSuite) TestName(c *qt.C) {
	c.Assert(s.idp.Name(), qt.Equals, "test")
}

func (s *testSuite) TestDescription(c *qt.C) {
	c.Assert(s.idp.Description(), qt.Equals, "Test")
}

func (s *testSuite) TestInteractive(c *qt.C) {
	c.Assert(s.idp.Interactive(), qt.Equals, true)
}

func (s *testSuite) TestURL(c *qt.C) {
	err := s.idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, "https://idp.test"))
	c.Assert(err, qt.Equals, nil)
	u := s.idp.URL("1")
	c.Assert(u, qt.Equals, "https://idp.test/login?id=1")
}

func (s *testSuite) TestHandleGet(c *qt.C) {
	err := s.idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, "https://idp.test"))
	c.Assert(err, qt.Equals, nil)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)
	c.Assert(err, qt.Equals, nil)
	s.idp.Handle(s.idptest.Ctx, rr, req)
	s.idptest.AssertLoginNotComplete(c)
	qthttptest.AssertJSONResponse(c, rr, http.StatusOK,
		test.TestInteractiveLoginResponse{
			URL: "https://idp.test/login",
		},
	)
}

var handleTests = []struct {
	about       string
	createUser  *store.Identity
	req         *http.Request
	expectUser  string
	expectError string
}{{
	about: "login new user",
	req: testLogin(&params.User{
		Username:   "test1",
		ExternalID: "test:1",
		FullName:   "Test One",
	}),
	expectUser: "test1",
}, {
	about: "login username",
	createUser: &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "2"),
		Username:   "test2",
		Name:       "Test Two",
	},
	req: testLogin(&params.User{
		Username: "test2",
	}),
	expectUser: "test2",
}, {
	about: "login external id",
	createUser: &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "3"),
		Username:   "test3",
		Name:       "Test Three",
	},
	req: testLogin(&params.User{
		ExternalID: "test:3",
	}),
	expectUser: "test3",
}, {
	about: "unsupported method",
	req: &http.Request{
		Method: "PUT",
	},
	expectError: `PUT not allowed`,
}, {
	about: "bad request",
	req: &http.Request{
		Method: "POST",
		Body:   ioutil.NopCloser(strings.NewReader("")),
	},
	expectError: `cannot unmarshal into field User: unexpected content type ""; want application/json; content: ""`,
}, {
	about: "login username not found",
	req: testLogin(&params.User{
		Username: "test4",
	}),
	expectError: `user test4 not found`,
}, {
	about: "login external id not found",
	req: testLogin(&params.User{
		ExternalID: "test:5",
	}),
	expectError: `identity "test:5" not found`,
}, {
	about: "login upsert clash",
	createUser: &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "6"),
		Username:   "test6",
		Name:       "Test Six",
	},
	req: testLogin(&params.User{
		Username:   "test6",
		ExternalID: "test:7",
		FullName:   "Test Seven",
	}),
	expectError: `username test6 already in use`,
}}

func (s *testSuite) TestHandle(c *qt.C) {
	ctx := s.idptest.Ctx
	for _, test := range handleTests {
		c.Run(test.about, func(c *qt.C) {
			if test.createUser != nil {
				err := s.idptest.Store.Store.UpdateIdentity(ctx, test.createUser, store.Update{
					store.Username: store.Set,
					store.Name:     store.Set,
				})
				c.Assert(err, qt.Equals, nil)
			}
			err := s.idp.Init(ctx, s.idptest.InitParams(c, "https://idp.test"))
			c.Assert(err, qt.Equals, nil)
			rr := httptest.NewRecorder()
			s.idp.Handle(ctx, rr, test.req)
			if test.expectError != "" {
				s.idptest.AssertLoginFailureMatches(c, test.expectError)
				return
			}
			s.idptest.AssertLoginSuccess(c, test.expectUser)
		})
	}
}

func testLogin(u *params.User) *http.Request {
	body, err := json.Marshal(u)
	if err != nil {
		panic(err)
	}
	req, err := http.NewRequest("POST", "/login", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func (s *testSuite) TestGetGroups(c *qt.C) {
	s.groups = []string{"g1", "g2"}
	groups, err := s.idp.GetGroups(context.Background(), nil)
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"g1", "g2"})
}
