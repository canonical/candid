// Copyright 2015 Canonical Ltd.

package idp_test

import (
	"net/http"
	"net/http/httptest"

	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/idp"
	"github.com/CanonicalLtd/blues-identity/internal/idtesting/mockusso"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/garyburd/go-oauth/oauth"
)

type ussoOAuthSuite struct {
	idpSuite
	mockusso.Suite
	idp *idp.USSOOAuthIdentityProvider
}

var _ = gc.Suite(&ussoOAuthSuite{})

func (s *ussoOAuthSuite) SetUpTest(c *gc.C) {
	s.idpSuite.SetUpTest(c)
	s.Suite.SetUpTest(c)
	s.idp = &idp.USSOOAuthIdentityProvider{}
}

func (s *ussoOAuthSuite) TearDownTest(c *gc.C) {
	s.Suite.TearDownTest(c)
	s.idpSuite.TearDownTest(c)
}

func (s *ussoOAuthSuite) TestName(c *gc.C) {
	c.Assert(s.idp.Name(), gc.Equals, "usso_oauth")
}

func (s *ussoOAuthSuite) TestDescription(c *gc.C) {
	c.Assert(s.idp.Description(), gc.Equals, "Ubuntu SSO OAuth")
}

func (s *ussoOAuthSuite) TestInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, false)
}

func (s *ussoOAuthSuite) TestURL(c *gc.C) {
	tc := &testContext{}
	u, err := s.idp.URL(tc, "1")
	c.Assert(err, gc.IsNil)
	c.Assert(u, gc.Equals, "https://idp.test/oauth?waitid=1")
}

func (s *ussoOAuthSuite) TestHandleSuccess(c *gc.C) {
	tc := testContext{
		store:      s.store,
		requestURL: "http://example.com/oauth?waitid=2",
	}
	err := s.store.UpsertIdentity(&mongodoc.Identity{
		ExternalID: "https://login.ubuntu.com/+id/test",
		Username:   "test",
		FullName:   "Test User",
		Email:      "test@example.com",
	})
	c.Assert(err, gc.IsNil)
	s.MockUSSO.AddUser(&mockusso.User{
		ID:             "test",
		NickName:       "test",
		FullName:       "Test User",
		Email:          "test@example.com",
		ConsumerSecret: "secret1",
		TokenKey:       "test-token",
		TokenSecret:    "secret2",
	})
	oc := &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  "test",
			Secret: "secret1",
		},
		SignatureMethod: oauth.HMACSHA1,
	}
	tc.params.Request, err = http.NewRequest("GET", tc.requestURL, nil)
	c.Assert(err, gc.IsNil)
	err = oc.SetAuthorizationHeader(
		tc.params.Request.Header,
		&oauth.Credentials{
			Token:  "test-token",
			Secret: "secret2",
		},
		tc.params.Request.Method,
		tc.params.Request.URL,
		nil,
	)
	c.Assert(err, gc.IsNil)
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	tc.success = true
	s.idp.Handle(&tc)
	c.Assert(tc.err, gc.IsNil)
	c.Assert(tc.macaroon, gc.Not(gc.IsNil))
	c.Assert(rr.Body.String(), gc.Equals, "login successful as user test\n")
}

func (s *ussoOAuthSuite) TestHandleVerifyFail(c *gc.C) {
	tc := testContext{
		store:      s.store,
		requestURL: "http://example.com/oauth?waitid=2",
	}
	err := s.store.UpsertIdentity(&mongodoc.Identity{
		ExternalID: "https://login.ubuntu.com/+id/test",
		Username:   "test",
		FullName:   "Test User",
		Email:      "test@example.com",
	})
	c.Assert(err, gc.IsNil)
	s.MockUSSO.AddUser(&mockusso.User{
		ID:             "test",
		NickName:       "test",
		FullName:       "Test User",
		Email:          "test@example.com",
		ConsumerSecret: "secret1",
		TokenKey:       "test-token",
		TokenSecret:    "secret2",
	})
	oc := &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  "test",
			Secret: "secret1",
		},
		SignatureMethod: oauth.HMACSHA1,
	}
	tc.params.Request, err = http.NewRequest("GET", tc.requestURL, nil)
	c.Assert(err, gc.IsNil)
	err = oc.SetAuthorizationHeader(
		tc.params.Request.Header,
		&oauth.Credentials{
			Token:  "test-token2",
			Secret: "secret2",
		},
		tc.params.Request.Method,
		tc.params.Request.URL,
		nil,
	)
	c.Assert(err, gc.IsNil)
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	s.idp.Handle(&tc)
	c.Assert(tc.err, gc.ErrorMatches, `invalid OAuth credentials`)
	c.Assert(tc.macaroon, gc.IsNil)
}
