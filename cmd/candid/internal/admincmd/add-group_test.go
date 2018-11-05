// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"golang.org/x/net/context"

	"github.com/CanonicalLtd/candid/store"
)

type addGroupSuite struct {
	fixture *fixture
}

func TestAddGroup(t *testing.T) {
	qtsuite.Run(qt.New(t), &addGroupSuite{})
}

func (s *addGroupSuite) Init(c *qt.C) {
	s.fixture = newFixture(c)
}

func (s *addGroupSuite) TestAddGroup(c *qt.C) {
	ctx := context.Background()
	s.fixture.server.AddIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
	})
	s.fixture.CheckNoOutput(c, "add-group", "-a", "admin.agent", "-u", "bob", "test1", "test2")
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
	}
	err := s.fixture.server.Store.Identity(ctx, &identity)
	c.Assert(err, qt.Equals, nil)
	c.Assert(identity.Groups, qt.DeepEquals, []string{"test1", "test2"})
}

func (s *addGroupSuite) TestAddGroupForEmail(c *qt.C) {
	ctx := context.Background()
	s.fixture.server.AddIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Email:      "bob@example.com",
	})
	s.fixture.CheckNoOutput(c, "add-group", "-a", "admin.agent", "-e", "bob@example.com", "test1", "test2")
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
	}
	err := s.fixture.server.Store.Identity(ctx, &identity)
	c.Assert(err, qt.Equals, nil)
	c.Assert(identity.Groups, qt.DeepEquals, []string{"test1", "test2"})
}

func (s *addGroupSuite) TestAddGroupForEmailNotFound(c *qt.C) {
	s.fixture.CheckError(
		c,
		1,
		`no user found for email "alice@example.com"`,
		"add-group", "-a", "admin.agent", "-e", "alice@example.com", "test1", "test2",
	)
}

func (s *addGroupSuite) TestAddGroupForEmailMultipleUsers(c *qt.C) {
	ctx := context.Background()
	identities := []store.Identity{{
		ProviderID: store.MakeProviderIdentity("test", "alice"),
		Username:   "alice",
		Email:      "bob@example.com",
	}, {
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Email:      "bob@example.com",
	}}
	for _, id := range identities {
		s.fixture.server.AddIdentity(ctx, &id)
	}
	s.fixture.CheckError(
		c,
		1,
		`more than one user found with email "bob@example.com" \(alice, bob\)`,
		"add-group", "-a", "admin.agent", "-e", "bob@example.com", "test1", "test2",
	)
}

func (s *addGroupSuite) TestAddGroupNoUser(c *qt.C) {
	s.fixture.CheckError(
		c,
		2,
		`no user specified, please specify either username or email`,
		"add-group", "-a", "admin.agent", "test1", "test2",
	)
}

func (s *addGroupSuite) TestAddGroupUserAndEmail(c *qt.C) {
	s.fixture.CheckError(
		c,
		2,
		`both username and email specified, please specify either username or email`,
		"add-group", "-a", "admin.agent", "-u", "bob", "-e", "bob@example.com", "test1", "test2",
	)
}
