// Copyright 2015 Canonical Ltd.

package v1_test

import (
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/juju/idmclient/params"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/test"
)

type loginSuite struct {
	apiSuite
	netSrv *httptest.Server
}

var _ = gc.Suite(&loginSuite{})

func (s *loginSuite) SetUpSuite(c *gc.C) {
	s.apiSuite.idps = []idp.IdentityProvider{
		test.IdentityProvider,
	}
	s.apiSuite.SetUpSuite(c)
}

func (s *loginSuite) SetUpTest(c *gc.C) {
	s.apiSuite.SetUpTest(c)
	s.netSrv = httptest.NewServer(s.srv)
}

func (s *loginSuite) TearDownTest(c *gc.C) {
	s.netSrv.Close()
	s.apiSuite.TearDownTest(c)
}

func (s *loginSuite) TearDownSuite(c *gc.C) {
	s.apiSuite.TearDownSuite(c)
}

func (s *loginSuite) TestInteractiveLogin(c *gc.C) {
	jar := &testCookieJar{}
	client := httpbakery.NewClient()
	visitor := test.Visitor{
		User: &params.User{
			Username:   "test",
			ExternalID: "http://example.com/+id/test",
			FullName:   "Test User",
			Email:      "test@example.com",
			IDPGroups:  []string{"test1", "test2"},
		},
	}
	u, err := url.Parse(location + "/v1/idp/test/login")
	c.Assert(err, gc.IsNil)
	err = visitor.VisitWebPage(testContext, client, map[string]*url.URL{httpbakery.UserInteractionMethod: u})
	c.Assert(err, gc.IsNil)
	c.Assert(jar.cookies, gc.HasLen, 0)
	st := s.pool.GetNoLimit()
	defer st.Close()
	id, err := st.GetIdentity("test")
	c.Assert(err, gc.IsNil)
	c.Assert(id.LastLogin.After(time.Now().Add(-1*time.Second)), gc.Equals, true)
}

func (s *loginSuite) TestNonInteractiveLogin(c *gc.C) {
	jar := &testCookieJar{}
	client := httpbakery.NewClient()
	visitor := test.Visitor{
		User: &params.User{
			Username:   "test",
			ExternalID: "http://example.com/+id/test",
			FullName:   "Test User",
			Email:      "test@example.com",
			IDPGroups:  []string{"test1", "test2"},
		},
	}
	u, err := url.Parse(location + "/v1/idp/test/login")
	c.Assert(err, gc.IsNil)
	err = visitor.VisitWebPage(testContext, client, map[string]*url.URL{"test": u})
	c.Assert(err, gc.IsNil)
	c.Assert(jar.cookies, gc.HasLen, 0)
	st := s.pool.GetNoLimit()
	defer st.Close()
	id, err := st.GetIdentity("test")
	c.Assert(err, gc.IsNil)
	c.Assert(id.LastLogin.After(time.Now().Add(-1*time.Second)), gc.Equals, true)
}

func (s *loginSuite) TestLoginFailure(c *gc.C) {
	jar := &testCookieJar{}
	client := httpbakery.NewClient()
	visitor := test.Visitor{
		User: &params.User{},
	}
	u, err := url.Parse(location + "/v1/idp/test/login")
	c.Assert(err, gc.IsNil)
	err = visitor.VisitWebPage(testContext, client, map[string]*url.URL{httpbakery.UserInteractionMethod: u})
	c.Assert(err, gc.ErrorMatches, `Post https:.*: user "" not found: not found`)
	c.Assert(jar.cookies, gc.HasLen, 0)
}
