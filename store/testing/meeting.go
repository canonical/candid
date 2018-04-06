// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package testing

import (
	"fmt"
	"sort"
	"time"

	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/meeting"
)

// MeetingSuite contains a set of tests for meeting.Store
// implementations. The Store and PutAtTimeFunc parameters need to be
// set before calling SetUpTest.
type MeetingSuite struct {
	Store         meeting.Store
	PutAtTimeFunc func(context.Context, meeting.Store, string, string, time.Time) error

	ctx   context.Context
	close func()
}

func (s *MeetingSuite) SetUpSuite(c *gc.C) {}

func (s *MeetingSuite) TearDownSuite(c *gc.C) {}

func (s *MeetingSuite) SetUpTest(c *gc.C) {
	s.ctx, s.close = s.Store.Context(context.Background())
}

func (s *MeetingSuite) TearDownTest(c *gc.C) {
	s.close()
}

func (s *MeetingSuite) TestPutGetRemove(c *gc.C) {
	err := s.Store.Put(s.ctx, "x", "xaddr")
	c.Assert(err, gc.Equals, nil)
	err = s.Store.Put(s.ctx, "y", "yaddr")
	c.Assert(err, gc.Equals, nil)

	addr, err := s.Store.Get(s.ctx, "x")
	c.Assert(err, gc.Equals, nil)
	c.Assert(addr, gc.Equals, "xaddr")

	addr, err = s.Store.Get(s.ctx, "y")
	c.Assert(err, gc.Equals, nil)
	c.Assert(addr, gc.Equals, "yaddr")

	_, err = s.Store.Remove(s.ctx, "y")
	c.Assert(err, gc.Equals, nil)

	// Check it's idempotent.
	_, err = s.Store.Remove(s.ctx, "y")
	c.Assert(err, gc.Equals, nil)

	addr, err = s.Store.Get(s.ctx, "y")
	c.Assert(err, gc.ErrorMatches, "rendezvous not found, probably expired")

	addr, err = s.Store.Get(s.ctx, "x")
	c.Assert(err, gc.Equals, nil)
	c.Assert(addr, gc.Equals, "xaddr")
}

func (s *MeetingSuite) TestRemoveNothingRemoved(c *gc.C) {
	now := time.Now()

	allIds := make(map[string]bool)
	for i := 0; i < 10; i++ {
		id := fmt.Sprint("a", i)
		err := s.PutAtTimeFunc(s.ctx, s.Store, id, "a", now.Add(time.Duration(-i)*time.Second))
		c.Assert(err, gc.Equals, nil)
		allIds[id] = true

		id = fmt.Sprint("b", i)
		err = s.PutAtTimeFunc(s.ctx, s.Store, id, "b", now.Add(time.Duration(-i)*time.Second))
		c.Assert(err, gc.Equals, nil)
		allIds[id] = true
	}
	ids, err := s.Store.RemoveOld(s.ctx, "a", now.Add(time.Duration(-11)*time.Second))
	c.Assert(err, gc.Equals, nil)
	c.Assert(len(ids), gc.Equals, 0)
}

func (s *MeetingSuite) TestRemoveOld(c *gc.C) {
	now := time.Now()

	allIds := make(map[string]bool)
	for i := 0; i < 10; i++ {
		id := fmt.Sprint("a", i)
		err := s.PutAtTimeFunc(s.ctx, s.Store, id, "a", now.Add(time.Duration(-i)*time.Second))
		c.Assert(err, gc.Equals, nil)
		allIds[id] = true

		id = fmt.Sprint("b", i)
		err = s.PutAtTimeFunc(s.ctx, s.Store, id, "b", now.Add(time.Duration(-i)*time.Second))
		c.Assert(err, gc.Equals, nil)
		allIds[id] = true
	}
	ids, err := s.Store.RemoveOld(s.ctx, "a", now.Add(-5500*time.Millisecond))
	c.Assert(err, gc.Equals, nil)
	sort.Strings(ids)
	c.Assert(ids, gc.DeepEquals, []string{"a6", "a7", "a8", "a9"})
	for _, id := range ids {
		_, err = s.Store.Get(s.ctx, id)
		c.Assert(err, gc.ErrorMatches, "rendezvous not found, probably expired")
		delete(allIds, id)
	}
	for id := range allIds {
		_, err = s.Store.Get(s.ctx, id)
		c.Assert(err, gc.Equals, nil)
	}

	ids, err = s.Store.RemoveOld(s.ctx, "", now.Add(-1500*time.Millisecond))
	c.Assert(err, gc.Equals, nil)
	sort.Strings(ids)
	c.Assert(ids, gc.DeepEquals, []string{"a2", "a3", "a4", "a5", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9"})
	for _, id := range ids {
		_, err = s.Store.Get(s.ctx, id)
		c.Assert(err, gc.ErrorMatches, "rendezvous not found, probably expired")
		delete(allIds, id)
	}
	for id := range allIds {
		_, err = s.Store.Get(s.ctx, id)
		c.Assert(err, gc.Equals, nil)
	}
}

func (s *MeetingSuite) TestContext(c *gc.C) {
	ctx, close := s.Store.Context(s.ctx)
	defer close()
	c.Assert(ctx, gc.Equals, s.ctx)
}
