// Copyright 2015 Canonical Ltd.

package test_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/juju/idmclient/params"
	"github.com/juju/testing/httptesting"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/test"
)

type testSuite struct {
	idp idp.IdentityProvider
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
	s.idp = test.NewIdentityProvider(test.Params{
		Name: "test",
	})
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
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
	}
	u := s.idp.URL(tc, "1")
	c.Assert(u, gc.Equals, "https://idp.test/test-login?waitid=1")
}

func (s *testSuite) TestHandleGet(c *gc.C) {
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: "https://idp.test",
		Request: &http.Request{
			Method: "GET",
		},
	}
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	idptest.AssertLoginInProgress(c, tc)
	httptesting.AssertJSONResponse(c, rr, http.StatusOK,
		test.TestInteractiveLoginResponse{
			URL: "https://idp.test/test-login",
		},
	)
}

var handleTests = []struct {
	about       string
	createUser  *params.User
	req         *http.Request
	expectUser  *params.User
	expectError string
}{{
	about: "login new user",
	req: testLogin(&params.User{
		Username:   "test1",
		ExternalID: "https://example.com/+id/1",
		FullName:   "Test One",
	}),
	expectUser: &params.User{
		Username:   "test1",
		ExternalID: "https://example.com/+id/1",
		FullName:   "Test One",
	},
}, {
	about: "login username",
	createUser: &params.User{
		Username:   "test2",
		ExternalID: "https://example.com/+id/2",
		FullName:   "Test Two",
	},
	req: testLogin(&params.User{
		Username: "test2",
	}),
	expectUser: &params.User{
		Username:   "test2",
		ExternalID: "https://example.com/+id/2",
		FullName:   "Test Two",
	},
}, {
	about: "login external id",
	createUser: &params.User{
		Username:   "test3",
		ExternalID: "https://example.com/+id/3",
		FullName:   "Test Three",
	},
	req: testLogin(&params.User{
		ExternalID: "https://example.com/+id/3",
	}),
	expectUser: &params.User{
		Username:   "test3",
		ExternalID: "https://example.com/+id/3",
		FullName:   "Test Three",
	},
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
	expectError: `cannot find user "test4"`,
}, {
	about: "login external id not found",
	req: testLogin(&params.User{
		ExternalID: "https://example.com/+id/5",
	}),
	expectError: `cannot find external id "https://example.com/\+id/5"`,
}, {
	about: "login upsert clash",
	createUser: &params.User{
		Username:   "test6",
		ExternalID: "https://example.com/+id/6",
		FullName:   "Test Six",
	},
	req: testLogin(&params.User{
		Username:   "test7",
		ExternalID: "https://example.com/+id/6",
		FullName:   "Test Seven",
	}),
	expectError: `external id "https://example.com/\+id/6" already used`,
}}

func (s *testSuite) TestHandle(c *gc.C) {
	for i, test := range handleTests {
		c.Logf("%d. %s", i, test.about)
		tc := &idptest.TestContext{
			Context:   context.Background(),
			Bakery_:   bakery.New(bakery.BakeryParams{}),
			URLPrefix: "https://idp.test",
			Request:   test.req,
		}
		if test.createUser != nil {
			err := tc.UpdateUser(test.createUser)
			c.Assert(err, gc.IsNil)
		}
		rr := httptest.NewRecorder()
		s.idp.Handle(tc, rr, tc.Request)
		if test.expectError != "" {
			idptest.AssertLoginFailure(c, tc, test.expectError)
			continue
		}
		idptest.AssertLoginSuccess(c, tc, test.expectUser.Username)
		idptest.AssertUser(c, tc, test.expectUser)
	}
}

func testLogin(u *params.User) *http.Request {
	body, err := json.Marshal(u)
	if err != nil {
		panic(err)
	}
	req, err := http.NewRequest("POST", "https://idp.test/test-login", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}
