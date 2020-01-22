// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
)

type aclSuite struct {
	fixture *fixture
}

func TestACL(t *testing.T) {
	qtsuite.Run(qt.New(t), &aclSuite{})
}

func (s *aclSuite) Init(c *qt.C) {
	s.fixture = newFixture(c)
}

func (s *aclSuite) TestACLShow(c *qt.C) {
	err := s.fixture.server.ACLStore.Set(context.Background(), "read-user", []string{"admin@candid", "alice", "bob"})
	c.Assert(err, qt.Equals, nil)
	stdout := s.fixture.CheckSuccess(c, "-a", "admin.agent", "acl", "show", "read-user")
	c.Assert(stdout, qt.Equals, `
admin@candid
alice
bob
`[1:])
}

func (s *aclSuite) TestACLShowNoACL(c *qt.C) {
	s.fixture.CheckError(c, 2, `ACL name required`, "-a", "admin.agent", "acl", "show")
}

func (s *aclSuite) TestACLShowTwoACLs(c *qt.C) {
	s.fixture.CheckError(c, 2, `only one ACL may be specified`, "-a", "admin.agent", "acl", "show", "read-user", "write-user")
}

func (s *aclSuite) TestACLShowInvalid(c *qt.C) {
	s.fixture.CheckError(c, 1, `Get http://.*/acl/no-such-acl: ACL not found`, "-a", "admin.agent", "acl", "show", "no-such-acl")
}

func (s *aclSuite) TestACLGrant(c *qt.C) {
	s.fixture.CheckNoOutput(c, "-a", "admin.agent", "acl", "grant", "read-user", "alice", "bob")
	acl, err := s.fixture.server.ACLStore.Get(context.Background(), "read-user")
	c.Assert(err, qt.Equals, nil)
	c.Assert(acl, qt.DeepEquals, []string{"admin@candid", "alice", "bob", "userinfo@candid"})
}

func (s *aclSuite) TestACLGrantNoArguments(c *qt.C) {
	s.fixture.CheckError(c, 2, `ACL name and at least one user required`, "-a", "admin.agent", "acl", "grant")
}

func (s *aclSuite) TestACLGrantInvalid(c *qt.C) {
	s.fixture.CheckError(c, 1, `Post http://.*/acl/no-such-acl: ACL not found`, "-a", "admin.agent", "acl", "grant", "no-such-acl", "bob")
}

func (s *aclSuite) TestACLRevoke(c *qt.C) {
	err := s.fixture.server.ACLStore.Set(context.Background(), "read-user", []string{"admin@candid", "alice", "bob"})
	c.Assert(err, qt.Equals, nil)
	s.fixture.CheckNoOutput(c, "-a", "admin.agent", "acl", "revoke", "read-user", "bob")
	acl, err := s.fixture.server.ACLStore.Get(context.Background(), "read-user")
	c.Assert(err, qt.Equals, nil)
	c.Assert(acl, qt.DeepEquals, []string{"admin@candid", "alice"})
}

func (s *aclSuite) TestACLRevokeNoArguments(c *qt.C) {
	s.fixture.CheckError(c, 2, `ACL name and at least one user required`, "-a", "admin.agent", "acl", "revoke")
}

func (s *aclSuite) TestACLRevokeInvalid(c *qt.C) {
	s.fixture.CheckError(c, 1, `Post http://.*/acl/no-such-acl: ACL not found`, "-a", "admin.agent", "acl", "revoke", "no-such-acl", "bob")
}
