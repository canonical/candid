// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/store"
)

type removeGroupSuite struct {
	commandSuite
}

var _ = gc.Suite(&removeGroupSuite{})

func (s *removeGroupSuite) TestRemoveGroup(c *gc.C) {
	ctx := context.Background()
	s.server.AddIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Groups:     []string{"test1", "test2", "test3"},
	})
	s.CheckNoOutput(c, "remove-group", "-a", "admin.agent", "-u", "bob", "test1", "test2")
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
	}
	err := s.server.Store.Identity(ctx, &identity)
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity.Groups, jc.DeepEquals, []string{"test3"})
}

func (s *removeGroupSuite) TestRemoveGroupForEmail(c *gc.C) {
	ctx := context.Background()
	s.server.AddIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Email:      "bob@example.com",
		Groups:     []string{"test1", "test2", "test3"},
	})
	s.CheckNoOutput(c, "remove-group", "-a", "admin.agent", "-e", "bob@example.com", "test1", "test2")
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
	}
	err := s.server.Store.Identity(ctx, &identity)
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity.Groups, jc.DeepEquals, []string{"test3"})
}

func (s *removeGroupSuite) TestRemoveGroupForEmailNotFound(c *gc.C) {
	s.CheckError(
		c,
		1,
		`no user found for email "alice@example.com"`,
		"remove-group", "-a", "admin.agent", "-e", "alice@example.com", "test1", "test2",
	)
}

func (s *removeGroupSuite) TestRemoveGroupNoUser(c *gc.C) {
	s.CheckError(
		c,
		2,
		`no user specified, please specify either username or email`,
		"remove-group", "-a", "admin.agent", "test1", "test2",
	)
}
