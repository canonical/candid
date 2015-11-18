// Copyright 2015 Canonical Ltd.

package mgomeeting_test

import (
	"github.com/juju/testing"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/meeting/mgomeeting"
)

type storeSuite struct {
	testing.IsolatedMgoSuite
}

var _ = gc.Suite(&storeSuite{})

func (s *storeSuite) TestPutGetRemove(c *gc.C) {
	coll := s.Session.DB("idm-test").C("foo")

	store := mgomeeting.NewStore(coll)

	err := store.Put("x", "xaddr")
	c.Assert(err, gc.IsNil)
	err = store.Put("y", "yaddr")
	c.Assert(err, gc.IsNil)

	addr, err := store.Get("x")
	c.Assert(err, gc.IsNil)
	c.Assert(addr, gc.Equals, "xaddr")

	addr, err = store.Get("y")
	c.Assert(err, gc.IsNil)
	c.Assert(addr, gc.Equals, "yaddr")

	err = store.Remove("y")
	c.Assert(err, gc.IsNil)

	addr, err = store.Get("y")
	c.Assert(err, gc.ErrorMatches, "rendezvous not found, probably expired")

	addr, err = store.Get("x")
	c.Assert(err, gc.IsNil)
	c.Assert(addr, gc.Equals, "xaddr")
}
