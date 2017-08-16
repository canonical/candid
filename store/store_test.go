// Copyright 2017 Canonical Ltd.

package store_test

import (
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/store"
)

type storeSuite struct{}

var _ = gc.Suite(&storeSuite{})

func (*storeSuite) TestProviderIdentity(c *gc.C) {
	pid := store.MakeProviderIdentity("test", "test-id")
	c.Assert(pid, gc.Equals, store.ProviderIdentity("test:test-id"))
	prov, id := pid.Split()
	c.Assert(prov, gc.Equals, "test")
	c.Assert(id, gc.Equals, "test-id")
}
