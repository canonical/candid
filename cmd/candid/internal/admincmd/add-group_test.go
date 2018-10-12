// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"github.com/CanonicalLtd/candid/store"
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
)

type addGroupSuite struct {
	commandSuite
}

var _ = gc.Suite(&addGroupSuite{})

func (s *addGroupSuite) TestAddGroup(c *gc.C) {
	ctx := context.Background()
	s.server.AddIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
	})
	s.CheckNoOutput(c, "add-group", "-a", "admin.agent", "-u", "bob", "test1", "test2")
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
	}
	err := s.server.Store.Identity(ctx, &identity)
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity.Groups, jc.DeepEquals, []string{"test1", "test2"})
}

func (s *addGroupSuite) TestAddGroupForEmail(c *gc.C) {
	ctx := context.Background()
	s.server.AddIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Email:      "bob@example.com",
	})
	s.CheckNoOutput(c, "add-group", "-a", "admin.agent", "-e", "bob@example.com", "test1", "test2")
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
	}
	err := s.server.Store.Identity(ctx, &identity)
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity.Groups, jc.DeepEquals, []string{"test1", "test2"})
}

func (s *addGroupSuite) TestAddGroupForEmailNotFound(c *gc.C) {
	s.CheckError(
		c,
		1,
		`no user found for email "alice@example.com"`,
		"add-group", "-a", "admin.agent", "-e", "alice@example.com", "test1", "test2",
	)
}

func (s *addGroupSuite) TestAddGroupForEmailMultipleUsers(c *gc.C) {
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
		s.server.AddIdentity(ctx, &id)
	}
	s.CheckError(
		c,
		1,
		`more than one user found with email "bob@example.com" \(alice, bob\)`,
		"add-group", "-a", "admin.agent", "-e", "bob@example.com", "test1", "test2",
	)
}

func (s *addGroupSuite) TestAddGroupNoUser(c *gc.C) {
	s.CheckError(
		c,
		2,
		`no user specified, please specify either username or email`,
		"add-group", "-a", "admin.agent", "test1", "test2",
	)
}

func (s *addGroupSuite) TestAddGroupUserAndEmail(c *gc.C) {
	s.CheckError(
		c,
		2,
		`both username and email specified, please specify either username or email`,
		"add-group", "-a", "admin.agent", "-u", "bob", "-e", "bob@example.com", "test1", "test2",
	)
}
