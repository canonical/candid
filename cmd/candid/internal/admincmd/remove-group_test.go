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

type removeGroupSuite struct {
	fixture *fixture
}

func TestRemoveGroup(t *testing.T) {
	qtsuite.Run(qt.New(t), &removeGroupSuite{})
}

func (s *removeGroupSuite) Init(c *qt.C) {
	s.fixture = newFixture(c)
}

func (s *removeGroupSuite) TestRemoveGroup(c *qt.C) {
	ctx := context.Background()
	s.fixture.server.AddIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Groups:     []string{"test1", "test2", "test3"},
	})
	s.fixture.CheckNoOutput(c, "remove-group", "-a", "admin.agent", "-u", "bob", "test1", "test2")
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
	}
	err := s.fixture.server.Store.Identity(ctx, &identity)
	c.Assert(err, qt.Equals, nil)
	c.Assert(identity.Groups, qt.DeepEquals, []string{"test3"})
}

func (s *removeGroupSuite) TestRemoveGroupForEmail(c *qt.C) {
	ctx := context.Background()
	s.fixture.server.AddIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Email:      "bob@example.com",
		Groups:     []string{"test1", "test2", "test3"},
	})
	s.fixture.CheckNoOutput(c, "remove-group", "-a", "admin.agent", "-e", "bob@example.com", "test1", "test2")
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
	}
	err := s.fixture.server.Store.Identity(ctx, &identity)
	c.Assert(err, qt.Equals, nil)
	c.Assert(identity.Groups, qt.DeepEquals, []string{"test3"})
}

func (s *removeGroupSuite) TestRemoveGroupForEmailNotFound(c *qt.C) {
	s.fixture.CheckError(
		c,
		1,
		`no user found for email "alice@example.com"`,
		"remove-group", "-a", "admin.agent", "-e", "alice@example.com", "test1", "test2",
	)
}

func (s *removeGroupSuite) TestRemoveGroupNoUser(c *qt.C) {
	s.fixture.CheckError(
		c,
		2,
		`no user specified, please specify either username or email`,
		"remove-group", "-a", "admin.agent", "test1", "test2",
	)
}
