// Copyright 2015 Canonical Ltd.

package mgomeeting_test

import (
	"fmt"
	"sort"
	"time"

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

	// Check it's idempotent.
	err = store.Remove("y")
	c.Assert(err, gc.IsNil)

	addr, err = store.Get("y")
	c.Assert(err, gc.ErrorMatches, "rendezvous not found, probably expired")

	addr, err = store.Get("x")
	c.Assert(err, gc.IsNil)
	c.Assert(addr, gc.Equals, "xaddr")
}

func (s *storeSuite) TestRemoveOld(c *gc.C) {
	coll := s.Session.DB("idm-test").C("foo")

	now := time.Now()

	err := mgomeeting.CreateCollection(coll)
	c.Assert(err, gc.IsNil)

	store := mgomeeting.NewStore(coll)
	allIds := make(map[string]bool)
	for i := 0; i < 10; i++ {
		id := fmt.Sprint("a", i)
		err := mgomeeting.PutAtTime(store, id, "a", now.Add(time.Duration(-i)*time.Second))
		c.Assert(err, gc.IsNil)
		allIds[id] = true

		id = fmt.Sprint("b", i)
		err = mgomeeting.PutAtTime(store, id, "b", now.Add(time.Duration(-i)*time.Second))
		c.Assert(err, gc.IsNil)
		allIds[id] = true
	}
	ids, err := store.RemoveOld("a", now.Add(-5500*time.Millisecond))
	c.Assert(err, gc.IsNil)
	sort.Strings(ids)
	c.Assert(ids, gc.DeepEquals, []string{"a6", "a7", "a8", "a9"})
	for _, id := range ids {
		_, err = store.Get(id)
		c.Assert(err, gc.ErrorMatches, "rendezvous not found, probably expired")
		delete(allIds, id)
	}
	for id := range allIds {
		_, err = store.Get(id)
		c.Assert(err, gc.IsNil)
	}

	ids, err = store.RemoveOld("", now.Add(-1500*time.Millisecond))
	c.Assert(err, gc.IsNil)
	sort.Strings(ids)
	c.Assert(ids, gc.DeepEquals, []string{"a2", "a3", "a4", "a5", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9"})
	for _, id := range ids {
		_, err = store.Get(id)
		c.Assert(err, gc.ErrorMatches, "rendezvous not found, probably expired")
		delete(allIds, id)
	}
	for id := range allIds {
		_, err = store.Get(id)
		c.Assert(err, gc.IsNil)
	}
}
