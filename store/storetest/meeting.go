// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package storetest

import (
	"context"
	"fmt"
	"sort"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"

	"github.com/canonical/candid/meeting"
)

// meetingSuite contains a set of tests for meeting.Store
// implementations.
type meetingSuite struct {
	newStore func(c *qt.C) meeting.Store

	Store         meeting.Store
	PutAtTimeFunc func(context.Context, meeting.Store, string, string, time.Time) error

	ctx context.Context
}

// TestMeetingStore tests the given store. The putAtTime function
// should put an item in the store as if it had been put there
// at the given time.
func TestMeetingStore(
	c *qt.C,
	newStore func(c *qt.C) meeting.Store,
	putAtTime func(ctx context.Context, s meeting.Store, id, address string, now time.Time) error,
) {
	qtsuite.Run(c, &meetingSuite{
		newStore:      newStore,
		PutAtTimeFunc: putAtTime,
	})
}

func (s *meetingSuite) Init(c *qt.C) {
	s.Store = s.newStore(c)
	ctx, close := s.Store.Context(context.Background())
	s.ctx = ctx
	c.Cleanup(close)
}

func (s *meetingSuite) TestPutGetRemove(c *qt.C) {
	err := s.Store.Put(s.ctx, "x", "xaddr")
	c.Assert(err, qt.IsNil)
	err = s.Store.Put(s.ctx, "y", "yaddr")
	c.Assert(err, qt.IsNil)

	addr, err := s.Store.Get(s.ctx, "x")
	c.Assert(err, qt.IsNil)
	c.Assert(addr, qt.Equals, "xaddr")

	addr, err = s.Store.Get(s.ctx, "y")
	c.Assert(err, qt.IsNil)
	c.Assert(addr, qt.Equals, "yaddr")

	_, err = s.Store.Remove(s.ctx, "y")
	c.Assert(err, qt.IsNil)

	// Check it's idempotent.
	_, err = s.Store.Remove(s.ctx, "y")
	c.Assert(err, qt.IsNil)

	addr, err = s.Store.Get(s.ctx, "y")
	c.Assert(err, qt.ErrorMatches, "rendezvous not found, probably expired")
	c.Assert(addr, qt.Equals, "")

	addr, err = s.Store.Get(s.ctx, "x")
	c.Assert(err, qt.IsNil)
	c.Assert(addr, qt.Equals, "xaddr")
}

func (s *meetingSuite) TestRemoveNothingRemoved(c *qt.C) {
	now := time.Now()

	allIds := make(map[string]bool)
	for i := 0; i < 10; i++ {
		id := fmt.Sprint("a", i)
		err := s.PutAtTimeFunc(s.ctx, s.Store, id, "a", now.Add(time.Duration(-i)*time.Second))
		c.Assert(err, qt.IsNil)
		allIds[id] = true

		id = fmt.Sprint("b", i)
		err = s.PutAtTimeFunc(s.ctx, s.Store, id, "b", now.Add(time.Duration(-i)*time.Second))
		c.Assert(err, qt.IsNil)
		allIds[id] = true
	}
	ids, err := s.Store.RemoveOld(s.ctx, "a", now.Add(time.Duration(-11)*time.Second))
	c.Assert(err, qt.IsNil)
	c.Assert(len(ids), qt.Equals, 0)
}

func (s *meetingSuite) TestRemoveOld(c *qt.C) {
	now := time.Now()

	allIds := make(map[string]bool)
	for i := 0; i < 10; i++ {
		id := fmt.Sprint("a", i)
		err := s.PutAtTimeFunc(s.ctx, s.Store, id, "a", now.Add(time.Duration(-i)*time.Second))
		c.Assert(err, qt.IsNil)
		allIds[id] = true

		id = fmt.Sprint("b", i)
		err = s.PutAtTimeFunc(s.ctx, s.Store, id, "b", now.Add(time.Duration(-i)*time.Second))
		c.Assert(err, qt.IsNil)
		allIds[id] = true
	}
	ids, err := s.Store.RemoveOld(s.ctx, "a", now.Add(-5500*time.Millisecond))
	c.Assert(err, qt.IsNil)
	sort.Strings(ids)
	c.Assert(ids, qt.DeepEquals, []string{"a6", "a7", "a8", "a9"})
	for _, id := range ids {
		_, err = s.Store.Get(s.ctx, id)
		c.Assert(err, qt.ErrorMatches, "rendezvous not found, probably expired")
		delete(allIds, id)
	}
	for id := range allIds {
		_, err = s.Store.Get(s.ctx, id)
		c.Assert(err, qt.IsNil)
	}

	ids, err = s.Store.RemoveOld(s.ctx, "", now.Add(-1500*time.Millisecond))
	c.Assert(err, qt.IsNil)
	sort.Strings(ids)
	c.Assert(ids, qt.DeepEquals, []string{"a2", "a3", "a4", "a5", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9"})
	for _, id := range ids {
		_, err = s.Store.Get(s.ctx, id)
		c.Assert(err, qt.ErrorMatches, "rendezvous not found, probably expired")
		delete(allIds, id)
	}
	for id := range allIds {
		_, err = s.Store.Get(s.ctx, id)
		c.Assert(err, qt.IsNil)
	}
}

func (s *meetingSuite) TestPutSameIDTwice(c *qt.C) {
	err := s.Store.Put(s.ctx, "x", "addr1")
	c.Assert(err, qt.IsNil)
	// Putting the same id should result in an error.
	err = s.Store.Put(s.ctx, "x", "addr2")
	if err == nil {
		c.Errorf("expected error from putting same id twice; got no error")
	}
}

func (s *meetingSuite) TestContext(c *qt.C) {
	ctx, close := s.Store.Context(s.ctx)
	defer close()
	c.Assert(ctx, qt.Equals, s.ctx)
}
