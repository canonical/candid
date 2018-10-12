// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package static_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idptest"
	"github.com/CanonicalLtd/candid/idp/static"
	"github.com/CanonicalLtd/candid/store"
)

type staticSuite struct {
	idptest.Suite
}

var _ = gc.Suite(&staticSuite{})

func (s *staticSuite) setupIdp(c *gc.C, params static.Params) idp.IdentityProvider {
	i := static.NewIdentityProvider(params)
	i.Init(context.TODO(), s.InitParams(c, "https://example.com/test"))
	return i
}

func (s *staticSuite) getSampleParams() static.Params {
	return static.Params{
		Name: "test",
		Users: map[string]static.UserInfo{
			"user1": static.UserInfo{
				Password: "pass1",
				Name:     "User One",
				Email:    "user1@example.com",
				Groups:   []string{"group1", "group2"},
			},
		},
	}
}

func (s *staticSuite) makeLoginRequest(c *gc.C, i idp.IdentityProvider, username, password string) *httptest.ResponseRecorder {
	req, err := http.NewRequest("POST", "/login",
		strings.NewReader(
			url.Values{
				"username": {username},
				"password": {password},
			}.Encode(),
		),
	)
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rr := httptest.NewRecorder()
	i.Handle(context.TODO(), rr, req)
	return rr
}

func (s *staticSuite) TestName(c *gc.C) {
	idp := static.NewIdentityProvider(s.getSampleParams())
	c.Assert(idp.Name(), gc.Equals, "test")
}

func (s *staticSuite) TestDomain(c *gc.C) {
	params := s.getSampleParams()
	params.Domain = "domain"
	idp := static.NewIdentityProvider(params)
	c.Assert(idp.Domain(), gc.Equals, "domain")
}

func (s *staticSuite) TestInteractive(c *gc.C) {
	idp := static.NewIdentityProvider(s.getSampleParams())
	c.Assert(idp.Interactive(), gc.Equals, true)
}

func (s *staticSuite) TestHandle(c *gc.C) {
	i := s.setupIdp(c, s.getSampleParams())
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.AssertLoginSuccess(c, "user1")
	s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1"),
		Username:   "user1",
		Name:       "User One",
		Email:      "user1@example.com",
	})
}

func (s *staticSuite) TestHandleWithDomain(c *gc.C) {
	params := s.getSampleParams()
	params.Domain = "domain"
	i := s.setupIdp(c, params)
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.AssertLoginSuccess(c, "user1@domain")
	s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1@domain"),
		Username:   "user1@domain",
		Name:       "User One",
		Email:      "user1@example.com",
	})
}

func (s *staticSuite) TestGetGroups(c *gc.C) {
	params := s.getSampleParams()
	i := s.setupIdp(c, params)
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.AssertLoginSuccess(c, "user1")
	identity := s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1"),
		Username:   "user1",
		Name:       "User One",
		Email:      "user1@example.com",
	})
	groups, err := i.GetGroups(s.Ctx, identity)
	c.Assert(err, gc.Equals, nil)
	c.Assert(groups, gc.DeepEquals, []string{"group1", "group2"})
}

func (s *staticSuite) TestGetGroupsWithDomain(c *gc.C) {
	params := s.getSampleParams()
	params.Domain = "domain"
	i := s.setupIdp(c, params)
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.AssertLoginSuccess(c, "user1@domain")
	identity := s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1@domain"),
		Username:   "user1@domain",
		Name:       "User One",
		Email:      "user1@example.com",
	})
	groups, err := i.GetGroups(s.Ctx, identity)
	c.Assert(err, gc.Equals, nil)
	c.Assert(groups, gc.DeepEquals, []string{"group1", "group2"})
}

func (s *staticSuite) TestHandleFailedLoginWrongPassword(c *gc.C) {
	i := s.setupIdp(c, s.getSampleParams())
	s.makeLoginRequest(c, i, "user1", "wrong-pass")
	s.AssertLoginFailureMatches(c, `authentication failed for user "user1"`)
}

func (s *staticSuite) TestHandleFailedLoginUnknownUser(c *gc.C) {
	i := s.setupIdp(c, s.getSampleParams())
	s.makeLoginRequest(c, i, "unknown", "pass")
	s.AssertLoginFailureMatches(c, `authentication failed for user "unknown"`)
}
