// Copyright 2015 Canonical Ltd.

package test_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"

	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/juju/idmclient.v1/params"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/test"
	"github.com/CanonicalLtd/blues-identity/store"
)

type testSuite struct {
	idptest.Suite
	idp    idp.IdentityProvider
	groups []string
}

var _ = gc.Suite(&testSuite{})

func (s *testSuite) TestConfig(c *gc.C) {
	configYaml := `
identity-providers:
 - type: test
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(configYaml), &conf)
	c.Assert(err, gc.IsNil)
	c.Assert(conf.IdentityProviders, gc.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), gc.Equals, "test")
}

func (s *testSuite) SetUpTest(c *gc.C) {
	s.Suite.SetUpTest(c)
	s.idp = test.NewIdentityProvider(test.Params{
		Name:      "test",
		GetGroups: s.getGroups,
	})
}

func (s *testSuite) getGroups(*store.Identity) ([]string, error) {
	return s.groups, nil
}

func (s *testSuite) TestName(c *gc.C) {
	c.Assert(s.idp.Name(), gc.Equals, "test")
}

func (s *testSuite) TestDescription(c *gc.C) {
	c.Assert(s.idp.Description(), gc.Equals, "Test")
}

func (s *testSuite) TestInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, true)
}

func (s *testSuite) TestURL(c *gc.C) {
	ctx := context.Background()
	err := s.idp.Init(ctx, s.InitParams(c, "https://idp.test"))
	c.Assert(err, gc.Equals, nil)
	u := s.idp.URL("1")
	c.Assert(u, gc.Equals, "https://idp.test/login?id=1")
}

func (s *testSuite) TestHandleGet(c *gc.C) {
	ctx := context.Background()
	err := s.idp.Init(ctx, s.InitParams(c, "https://idp.test"))
	c.Assert(err, gc.Equals, nil)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)
	c.Assert(err, gc.Equals, nil)
	s.idp.Handle(ctx, rr, req)
	s.AssertLoginNotComplete(c)
	httptesting.AssertJSONResponse(c, rr, http.StatusOK,
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

func (s *testSuite) TestHandle(c *gc.C) {
	ctx := context.Background()
	for i, test := range handleTests {
		c.Logf("%d. %s", i, test.about)
		if test.createUser != nil {
			err := s.Store.UpdateIdentity(ctx, test.createUser, store.Update{
				store.Username: store.Set,
				store.Name:     store.Set,
			})
			c.Assert(err, gc.Equals, nil)
		}
		err := s.idp.Init(ctx, s.InitParams(c, "https://idp.test"))
		c.Assert(err, gc.Equals, nil)
		rr := httptest.NewRecorder()
		s.idp.Handle(ctx, rr, test.req)
		if test.expectError != "" {
			s.AssertLoginFailureMatches(c, test.expectError)
			continue
		}
		s.AssertLoginSuccess(c, test.expectUser)
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

func (s *testSuite) TestGetGroups(c *gc.C) {
	s.groups = []string{"g1", "g2"}
	groups, err := s.idp.GetGroups(context.Background(), nil)
	c.Assert(err, gc.Equals, nil)
	c.Assert(groups, jc.DeepEquals, []string{"g1", "g2"})
}
