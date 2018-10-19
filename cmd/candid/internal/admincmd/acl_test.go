// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
)

type aclSuite struct {
	commandSuite
}

var _ = gc.Suite(&aclSuite{})

func (s *aclSuite) TestACLShow(c *gc.C) {
	err := s.server.ACLStore.Set(context.Background(), "read-user", []string{"admin@candid", "alice", "bob"})
	c.Assert(err, gc.Equals, nil)
	stdout := s.CheckSuccess(c, "-a", "admin.agent", "acl", "show", "read-user")
	c.Assert(stdout, gc.Equals, `
admin@candid
alice
bob
`[1:])
}

func (s *aclSuite) TestACLShowNoACL(c *gc.C) {
	s.CheckError(c, 2, `ACL name required`, "-a", "admin.agent", "acl", "show")
}

func (s *aclSuite) TestACLShowTwoACLs(c *gc.C) {
	s.CheckError(c, 2, `only one ACL may be specified`, "-a", "admin.agent", "acl", "show", "read-user", "write-user")
}

func (s *aclSuite) TestACLShowInvalid(c *gc.C) {
	s.CheckError(c, 1, `Get http://.*/acl/no-such-acl: ACL not found`, "-a", "admin.agent", "acl", "show", "no-such-acl")
}

func (s *aclSuite) TestACLGrant(c *gc.C) {
	s.CheckNoOutput(c, "-a", "admin.agent", "acl", "grant", "read-user", "alice", "bob")
	acl, err := s.server.ACLStore.Get(context.Background(), "read-user")
	c.Assert(err, gc.Equals, nil)
	c.Assert(acl, jc.DeepEquals, []string{"admin@candid", "alice", "bob"})
}

func (s *aclSuite) TestACLGrantNoArguments(c *gc.C) {
	s.CheckError(c, 2, `ACL name and at least one user required`, "-a", "admin.agent", "acl", "grant")
}

func (s *aclSuite) TestACLGrantInvalid(c *gc.C) {
	s.CheckError(c, 1, `Post http://.*/acl/no-such-acl: ACL not found`, "-a", "admin.agent", "acl", "grant", "no-such-acl", "bob")
}

func (s *aclSuite) TestACLRevoke(c *gc.C) {
	err := s.server.ACLStore.Set(context.Background(), "read-user", []string{"admin@candid", "alice", "bob"})
	c.Assert(err, gc.Equals, nil)
	s.CheckNoOutput(c, "-a", "admin.agent", "acl", "revoke", "read-user", "bob")
	acl, err := s.server.ACLStore.Get(context.Background(), "read-user")
	c.Assert(err, gc.Equals, nil)
	c.Assert(acl, jc.DeepEquals, []string{"admin@candid", "alice"})
}

func (s *aclSuite) TestACLRevokeNoArguments(c *gc.C) {
	s.CheckError(c, 2, `ACL name and at least one user required`, "-a", "admin.agent", "acl", "revoke")
}

func (s *aclSuite) TestACLRevokeInvalid(c *gc.C) {
	s.CheckError(c, 1, `Post http://.*/acl/no-such-acl: ACL not found`, "-a", "admin.agent", "acl", "revoke", "no-such-acl", "bob")
}
