// Copyright 2017 Canonical Ltd.

package mgoctx_test

import (
	"github.com/juju/testing"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/mgoctx"
)

type mgoctxSuite struct {
	testing.IsolatedMgoSuite
}

var _ = gc.Suite(&mgoctxSuite{})

func (*mgoctxSuite) TestContextWithoutValue(c *gc.C) {
	s := mgoctx.SessionFromContext(context.Background())
	c.Assert(s, gc.IsNil)
}

func (s *mgoctxSuite) TestContextWithValue(c *gc.C) {
	ctx := mgoctx.ContextWithSession(context.Background(), s.Session)
	session := mgoctx.SessionFromContext(ctx)
	c.Assert(session, gc.Equals, s.Session)
}
