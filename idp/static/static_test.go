// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package static_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"golang.org/x/net/context"

	"github.com/CanonicalLtd/candid/idp"
	idptest "github.com/CanonicalLtd/candid/idp/qtidptest"
	"github.com/CanonicalLtd/candid/idp/static"
	candidtest "github.com/CanonicalLtd/candid/internal/qtcandidtest"
	"github.com/CanonicalLtd/candid/store"
)

type staticSuite struct {
	idptest *idptest.Fixture
}

func TestStatic(t *testing.T) {
	qtsuite.Run(qt.New(t), &staticSuite{})
}

func (s *staticSuite) Init(c *qt.C) {
	s.idptest = idptest.NewFixture(c, candidtest.NewStore())
}

func (s *staticSuite) setupIdp(c *qt.C, params static.Params) idp.IdentityProvider {
	i := static.NewIdentityProvider(params)
	i.Init(context.TODO(), s.idptest.InitParams(c, "https://example.com/test"))
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

func (s *staticSuite) makeLoginRequest(c *qt.C, i idp.IdentityProvider, username, password string) *httptest.ResponseRecorder {
	req, err := http.NewRequest("POST", "/login",
		strings.NewReader(
			url.Values{
				"username": {username},
				"password": {password},
			}.Encode(),
		),
	)
	c.Assert(err, qt.Equals, nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rr := httptest.NewRecorder()
	i.Handle(context.TODO(), rr, req)
	return rr
}

func (s *staticSuite) TestName(c *qt.C) {
	idp := static.NewIdentityProvider(s.getSampleParams())
	c.Assert(idp.Name(), qt.Equals, "test")
}

func (s *staticSuite) TestDomain(c *qt.C) {
	params := s.getSampleParams()
	params.Domain = "domain"
	idp := static.NewIdentityProvider(params)
	c.Assert(idp.Domain(), qt.Equals, "domain")
}

func (s *staticSuite) TestInteractive(c *qt.C) {
	idp := static.NewIdentityProvider(s.getSampleParams())
	c.Assert(idp.Interactive(), qt.Equals, true)
}

func (s *staticSuite) TestHandle(c *qt.C) {
	i := s.setupIdp(c, s.getSampleParams())
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.idptest.AssertLoginSuccess(c, "user1")
	s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1"),
		Username:   "user1",
		Name:       "User One",
		Email:      "user1@example.com",
	})
}

func (s *staticSuite) TestHandleWithDomain(c *qt.C) {
	params := s.getSampleParams()
	params.Domain = "domain"
	i := s.setupIdp(c, params)
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.idptest.AssertLoginSuccess(c, "user1@domain")
	s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1@domain"),
		Username:   "user1@domain",
		Name:       "User One",
		Email:      "user1@example.com",
	})
}

func (s *staticSuite) TestGetGroups(c *qt.C) {
	params := s.getSampleParams()
	i := s.setupIdp(c, params)
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.idptest.AssertLoginSuccess(c, "user1")
	identity := s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1"),
		Username:   "user1",
		Name:       "User One",
		Email:      "user1@example.com",
	})
	groups, err := i.GetGroups(s.idptest.Ctx, identity)
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"group1", "group2"})
}

func (s *staticSuite) TestGetGroupsWithDomain(c *qt.C) {
	params := s.getSampleParams()
	params.Domain = "domain"
	i := s.setupIdp(c, params)
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.idptest.AssertLoginSuccess(c, "user1@domain")
	identity := s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1@domain"),
		Username:   "user1@domain",
		Name:       "User One",
		Email:      "user1@example.com",
	})
	groups, err := i.GetGroups(s.idptest.Ctx, identity)
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"group1", "group2"})
}

func (s *staticSuite) TestHandleFailedLoginWrongPassword(c *qt.C) {
	i := s.setupIdp(c, s.getSampleParams())
	s.makeLoginRequest(c, i, "user1", "wrong-pass")
	s.idptest.AssertLoginFailureMatches(c, `authentication failed for user "user1"`)
}

func (s *staticSuite) TestHandleFailedLoginUnknownUser(c *qt.C) {
	i := s.setupIdp(c, s.getSampleParams())
	s.makeLoginRequest(c, i, "unknown", "pass")
	s.idptest.AssertLoginFailureMatches(c, `authentication failed for user "unknown"`)
}
