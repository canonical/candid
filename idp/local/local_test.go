// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package local_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idptest"
	"github.com/CanonicalLtd/candid/idp/local"
	"github.com/CanonicalLtd/candid/store"
)

type localSuite struct {
	idptest.Suite
}

var _ = gc.Suite(&localSuite{})

func (s *localSuite) setupIdp(c *gc.C, params local.Params) idp.IdentityProvider {
	i, err := local.NewIdentityProvider(params)
	c.Assert(err, gc.IsNil)
	i.Init(context.TODO(), s.InitParams(c, "https://example.com/test"))
	return i
}

func (s *localSuite) getSampleParams() local.Params {
	return local.Params{
		Name: "test",
		Users: map[string]local.UserInfo{
			"user1": local.UserInfo{
				Password: "pass1",
				Groups:   []string{"group1", "group2"},
			},
		},
	}
}

func (s *localSuite) makeLoginRequest(c *gc.C, i idp.IdentityProvider, username, password string) *httptest.ResponseRecorder {
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

func (s *localSuite) TestName(c *gc.C) {
	idp, err := local.NewIdentityProvider(s.getSampleParams())
	c.Assert(err, gc.Equals, nil)
	c.Assert(idp.Name(), gc.Equals, "test")
}

func (s *localSuite) TestDomain(c *gc.C) {
	params := s.getSampleParams()
	params.Domain = "domain"
	idp, err := local.NewIdentityProvider(params)
	c.Assert(err, gc.Equals, nil)
	c.Assert(idp.Domain(), gc.Equals, "domain")
}

func (s *localSuite) TestMissingUsers(c *gc.C) {
	params := s.getSampleParams()
	params.Users = map[string]local.UserInfo{}
	idp, err := local.NewIdentityProvider(params)
	c.Assert(err, gc.ErrorMatches, "no 'users' defined")
	c.Assert(idp, gc.IsNil)
}

func (s *localSuite) TestInteractive(c *gc.C) {
	idp, err := local.NewIdentityProvider(s.getSampleParams())
	c.Assert(err, gc.Equals, nil)
	c.Assert(idp.Interactive(), gc.Equals, true)
}

func (s *localSuite) TestHandle(c *gc.C) {
	i := s.setupIdp(c, s.getSampleParams())
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.AssertLoginSuccess(c, "user1")
	s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1"),
		Username:   "user1",
		Name:       "user1",
		Email:      "user1",
	})
}

func (s *localSuite) TestHandleWithDomain(c *gc.C) {
	params := s.getSampleParams()
	params.Domain = "domain"
	i := s.setupIdp(c, params)
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.AssertLoginSuccess(c, "user1@domain")
	s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1@domain"),
		Username:   "user1@domain",
		Name:       "user1@domain",
		Email:      "user1@domain",
	})
}

func (s *localSuite) TestGetGroups(c *gc.C) {
	params := s.getSampleParams()
	i := s.setupIdp(c, params)
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.AssertLoginSuccess(c, "user1")
	identity := s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1"),
		Username:   "user1",
		Name:       "user1",
		Email:      "user1",
	})
	groups, err := i.GetGroups(s.Ctx, identity)
	c.Assert(err, gc.Equals, nil)
	c.Assert(groups, gc.DeepEquals, []string{"group1", "group2"})
}

func (s *localSuite) TestGetGroupsWithDomain(c *gc.C) {
	params := s.getSampleParams()
	params.Domain = "domain"
	i := s.setupIdp(c, params)
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.AssertLoginSuccess(c, "user1@domain")
	identity := s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1@domain"),
		Username:   "user1@domain",
		Name:       "user1@domain",
		Email:      "user1@domain",
	})
	groups, err := i.GetGroups(s.Ctx, identity)
	c.Assert(err, gc.Equals, nil)
	c.Assert(groups, gc.DeepEquals, []string{"group1", "group2"})
}

func (s *localSuite) TestHandleFailedLoginWrongPassword(c *gc.C) {
	i := s.setupIdp(c, s.getSampleParams())
	s.makeLoginRequest(c, i, "user1", "wrong-pass")
	s.AssertLoginFailureMatches(c, `authentication failed for user "user1"`)
}

func (s *localSuite) TestHandleFailedLoginUnknownUser(c *gc.C) {
	i := s.setupIdp(c, s.getSampleParams())
	s.makeLoginRequest(c, i, "unknown", "pass")
	s.AssertLoginFailureMatches(c, `authentication failed for user "unknown"`)
}
