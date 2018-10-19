// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package testing

import (
	"github.com/juju/aclstore/v2"
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
)

// ACLStoreSuite contains a set of tests for ACLStore implementations.
// The Store parameter need to be set before calling SetUpTest.
type ACLStoreSuite struct {
	Store aclstore.ACLStore
}

func (s *ACLStoreSuite) SetUpSuite(c *gc.C) {}

func (s *ACLStoreSuite) TearDownSuite(c *gc.C) {}

func (s *ACLStoreSuite) SetUpTest(c *gc.C) {}

func (s *ACLStoreSuite) TearDownTest(c *gc.C) {}

func (s *ACLStoreSuite) TestACLStore(c *gc.C) {
	err := s.Store.CreateACL(context.Background(), "test", []string{"test1"})
	c.Assert(err, gc.Equals, nil)
	acl, err := s.Store.Get(context.Background(), "test")
	c.Assert(err, gc.Equals, nil)
	c.Assert(acl, jc.DeepEquals, []string{"test1"})
	err = s.Store.Add(context.Background(), "test", []string{"test2"})
	c.Assert(err, gc.Equals, nil)
	acl, err = s.Store.Get(context.Background(), "test")
	c.Assert(err, gc.Equals, nil)
	c.Assert(acl, jc.DeepEquals, []string{"test1", "test2"})
}
