// Copyright 2015 Canonical Ltd.

package idp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"

	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/idp"
	"github.com/CanonicalLtd/blues-identity/internal/idtesting/mockusso"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
)

type ussoSuite struct {
	idpSuite
	mockusso.Suite
	idp *idp.USSOIdentityProvider
}

var _ = gc.Suite(&ussoSuite{})

func (s *ussoSuite) SetUpTest(c *gc.C) {
	s.idpSuite.SetUpTest(c)
	s.Suite.SetUpTest(c)
	s.idp = idp.NewUSSOIdentityProvider()
}

func (s *ussoSuite) TearDownTest(c *gc.C) {
	s.Suite.TearDownTest(c)
	s.idpSuite.TearDownTest(c)
}

func (s *ussoSuite) TestName(c *gc.C) {
	c.Assert(s.idp.Name(), gc.Equals, "usso")
}

func (s *ussoSuite) TestDescription(c *gc.C) {
	c.Assert(s.idp.Description(), gc.Equals, "Ubuntu SSO")
}

func (s *ussoSuite) TestInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, true)
}

func (s *ussoSuite) TestURL(c *gc.C) {
	tc := &testContext{}
	t, err := s.idp.URL(tc, "1")
	c.Assert(err, gc.IsNil)
	u, err := url.Parse(t)
	c.Assert(err, gc.IsNil)
	c.Assert(u.Host, gc.Equals, "login.ubuntu.com")
	c.Assert(u.Path, gc.Equals, "/+openid")
	q := u.Query()
	rt, err := url.Parse(q.Get("openid.return_to"))
	c.Assert(err, gc.IsNil)
	c.Assert(rt.Host, gc.Equals, "idp.test")
	c.Assert(rt.Path, gc.Equals, "/callback")
}

func (s *ussoSuite) TestHandleSuccess(c *gc.C) {
	var tc testContext
	tc.store = s.store
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.MockUSSO.SetLoginUser("test")
	cl := http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("no redirect")
		},
	}
	u, err := s.idp.URL(&tc, "2")
	c.Assert(err, gc.IsNil)
	resp, err := cl.Get(u)
	defer resp.Body.Close()
	tc.requestURL = resp.Header.Get("Location")
	tc.params.Request, err = http.NewRequest("GET", resp.Header.Get("Location"), nil)
	c.Assert(err, gc.IsNil)
	tc.params.Request.ParseForm()
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	tc.success = true
	s.idp.Handle(&tc)
	c.Assert(tc.err, gc.IsNil)
	c.Assert(tc.macaroon, gc.Not(gc.IsNil))
	c.Assert(rr.Body.String(), gc.Equals, "login successful as user test\n")
}

func (s *ussoSuite) TestHandleSuccessNoExtensions(c *gc.C) {
	var tc testContext
	tc.store = s.store
	err := s.store.UpsertIdentity(&mongodoc.Identity{
		ExternalID: "https://login.ubuntu.com/+id/test",
		Username:   "test",
		FullName:   "Test User",
		Email:      "test@example.com",
	})
	c.Assert(err, gc.IsNil)
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.MockUSSO.SetLoginUser("test")
	s.MockUSSO.ExcludeExtensions()
	cl := http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("no redirect")
		},
	}
	u, err := s.idp.URL(&tc, "2")
	c.Assert(err, gc.IsNil)
	resp, err := cl.Get(u)
	defer resp.Body.Close()
	tc.requestURL = resp.Header.Get("Location")
	tc.params.Request, err = http.NewRequest("GET", resp.Header.Get("Location"), nil)
	c.Assert(err, gc.IsNil)
	tc.params.Request.ParseForm()
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	tc.success = true
	s.idp.Handle(&tc)
	c.Assert(tc.err, gc.IsNil)
	c.Assert(tc.macaroon, gc.Not(gc.IsNil))
	c.Assert(rr.Body.String(), gc.Equals, "login successful as user test\n")
}

func (s *ussoSuite) TestHandleNoExtensionsNotFound(c *gc.C) {
	var tc testContext
	tc.store = s.store
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.MockUSSO.SetLoginUser("test")
	s.MockUSSO.ExcludeExtensions()
	cl := http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("no redirect")
		},
	}
	u, err := s.idp.URL(&tc, "2")
	c.Assert(err, gc.IsNil)
	resp, err := cl.Get(u)
	defer resp.Body.Close()
	tc.requestURL = resp.Header.Get("Location")
	tc.params.Request, err = http.NewRequest("GET", resp.Header.Get("Location"), nil)
	c.Assert(err, gc.IsNil)
	tc.params.Request.ParseForm()
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	tc.success = true
	s.idp.Handle(&tc)
	c.Assert(tc.err, gc.ErrorMatches, `cannot get user details for "https://login.ubuntu.com/\+id/test": not found`)
	c.Assert(tc.macaroon, gc.IsNil)
}
