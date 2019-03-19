// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package static_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idptest"
	"github.com/CanonicalLtd/candid/idp/static"
	"github.com/CanonicalLtd/candid/internal/candidtest"
	"github.com/CanonicalLtd/candid/store"
)

const idpPrefix = "https://idp.example.com"

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
	i.Init(context.TODO(), s.idptest.InitParams(c, idpPrefix))
	return i
}

func getSampleParams() static.Params {
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

func (s *staticSuite) TestName(c *qt.C) {
	idp := static.NewIdentityProvider(getSampleParams())
	c.Assert(idp.Name(), qt.Equals, "test")
}

func (s *staticSuite) TestDomain(c *qt.C) {
	params := getSampleParams()
	params.Domain = "domain"
	idp := static.NewIdentityProvider(params)
	c.Assert(idp.Domain(), qt.Equals, "domain")
}

func (s *staticSuite) TestInteractive(c *qt.C) {
	idp := static.NewIdentityProvider(getSampleParams())
	c.Assert(idp.Interactive(), qt.Equals, true)
}

func (s *staticSuite) TestHandle(c *qt.C) {
	i := s.setupIdp(c, getSampleParams())
	id, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "pass1"))
	c.Assert(err, qt.Equals, nil)
	candidtest.AssertEqualIdentity(c, id, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1"),
		Username:   "user1",
		Name:       "User One",
		Email:      "user1@example.com",
	})
	s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1"),
		Username:   "user1",
		Name:       "User One",
		Email:      "user1@example.com",
	})
}

func (s *staticSuite) TestHandleWithDomain(c *qt.C) {
	params := getSampleParams()
	params.Domain = "domain"
	i := s.setupIdp(c, params)
	id, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "pass1"))
	c.Assert(err, qt.Equals, nil)

	candidtest.AssertEqualIdentity(c, id, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1@domain"),
		Username:   "user1@domain",
		Name:       "User One",
		Email:      "user1@example.com",
	})
	s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1@domain"),
		Username:   "user1@domain",
		Name:       "User One",
		Email:      "user1@example.com",
	})
}

func (s *staticSuite) TestGetGroups(c *qt.C) {
	params := getSampleParams()
	i := s.setupIdp(c, params)
	_, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "pass1"))
	c.Assert(err, qt.Equals, nil)
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

func (s *staticSuite) TestGetGroupsReturnsNewSlice(c *qt.C) {
	params := getSampleParams()
	params.Domain = "domain"
	i := s.setupIdp(c, params)
	_, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "pass1"))
	c.Assert(err, qt.Equals, nil)
	identity := s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "user1@domain"),
		Username:   "user1@domain",
		Name:       "User One",
		Email:      "user1@example.com",
	})
	groups, err := i.GetGroups(s.idptest.Ctx, identity)
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"group1", "group2"})
	groups[0] = "group1@domain"
	groups, err = i.GetGroups(s.idptest.Ctx, identity)
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"group1", "group2"})
}

func (s *staticSuite) TestHandleFailedLoginWrongPassword(c *qt.C) {
	i := s.setupIdp(c, getSampleParams())
	_, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "wrong-pass"))
	c.Assert(err, qt.ErrorMatches, `authentication failed for user "user1"`)
}

func (s *staticSuite) TestHandleFailedLoginUnknownUser(c *qt.C) {
	i := s.setupIdp(c, getSampleParams())
	_, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("unknown", "pass"))
	c.Assert(err, qt.ErrorMatches, `authentication failed for user "unknown"`)
}
