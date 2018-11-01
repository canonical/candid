// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package storetest

import (
	"github.com/juju/aclstore/v2"
	"golang.org/x/net/context"
	qt "github.com/frankban/quicktest"
)

// TestACLStore runs tests on the given ACLStore implementation.
func TestACLStore(c *qt.C, newStore func(c *qt.C) aclstore.ACLStore) {
	store := newStore(c)
	err := store.CreateACL(context.Background(), "test", []string{"test1"})
	c.Assert(err, qt.Equals, nil)
	acl, err := store.Get(context.Background(), "test")
	c.Assert(err, qt.Equals, nil)
	c.Assert(acl, qt.DeepEquals, []string{"test1"})
	err = store.Add(context.Background(), "test", []string{"test2"})
	c.Assert(err, qt.Equals, nil)
	acl, err = store.Get(context.Background(), "test")
	c.Assert(err, qt.Equals, nil)
	c.Assert(acl, qt.DeepEquals, []string{"test1", "test2"})
}
