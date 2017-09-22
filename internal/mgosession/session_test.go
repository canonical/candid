// Copyright 2016 Canonical Ltd.

package mgosession_test

import (
	"time"

	jujutesting "github.com/juju/testing"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/mgosession"
)

type suite struct {
	jujutesting.IsolatedMgoSuite
}

var _ = gc.Suite(&suite{})

func (s *suite) TestSession(c *gc.C) {
	psession := jujutesting.NewProxiedSession(c)
	defer psession.Close()
	pool := mgosession.NewPool(psession.Session, 2)
	defer pool.Close()

	// Obtain a session from the pool, then kill its connection
	// so we can be sure that the next session is using a different
	// connection
	s0 := pool.Session()
	defer s0.Close()
	c.Assert(s0.Ping(), gc.IsNil)
	psession.CloseConns()
	c.Assert(s0.Ping(), gc.NotNil)

	// The next session should still work.
	s1 := pool.Session()
	defer s1.Close()
	c.Assert(s1.Ping(), gc.IsNil)

	// The third session should cycle back to the first
	// and fail.
	s2 := pool.Session()
	defer s2.Close()
	c.Assert(s2.Ping(), gc.NotNil)

	// Kill the connections again so that we
	// can be sure that the next session has been
	// copied.
	psession.CloseConns()
	c.Assert(s1.Ping(), gc.NotNil)

	// Resetting the pool should cause new sessions
	// to work again.
	pool.Reset()
	s3 := pool.Session()
	defer s3.Close()
	c.Assert(s3.Ping(), gc.IsNil)
	s4 := pool.Session()
	defer s4.Close()
	c.Assert(s4.Ping(), gc.IsNil)
}

func (s *suite) TestClosingPoolDoesNotClosePreviousSessions(c *gc.C) {
	pool := mgosession.NewPool(s.Session, 2)
	session := pool.Session()
	defer session.Close()
	pool.Close()
	c.Assert(session.Ping(), gc.Equals, nil)
}

func (s *suite) TestSessionPinger(c *gc.C) {
	t0 := time.Now()
	clock := jujutesting.NewClock(t0)
	s.PatchValue(&mgosession.Clock, clock)

	psession := jujutesting.NewProxiedSession(c)
	defer psession.Close()
	pool := mgosession.NewPool(psession.Session, 1)
	defer pool.Close()

	// Obtain a session from the pool, then kill its connection
	// so we tell whether the next session from the pool uses
	// the same connection.
	s0 := pool.Session()
	defer s0.Close()
	c.Assert(s0.Ping(), gc.IsNil)
	psession.CloseConns()
	c.Assert(s0.Ping(), gc.NotNil)

	// Sanity check that getting another session
	// also gives us one that fails.
	s1 := pool.Session()
	defer s1.Close()
	c.Assert(s0.Ping(), gc.NotNil)

	// Wait for the pinger to sleep.
	select {
	case <-clock.Alarms():
	case <-time.After(time.Second):
		c.Fatalf("timed out waiting for pinger to sleep")
	}
	clock.Advance(mgosession.PingInterval)

	// Wait for the pinger to sleep again after it's pinged
	// the session and found it wanting.
	select {
	case <-clock.Alarms():
	case <-time.After(time.Second):
		c.Fatalf("timed out waiting for pinger to sleep")
	}

	// Now the next session should be all fresh and lovely.
	s2 := pool.Session()
	defer s2.Close()
	c.Assert(s2.Ping(), gc.IsNil)
}
