// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore_test

import (
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/store/mgostore"
)

type bakerySuite struct {
	testing.IsolatedMgoSuite
}

var _ = gc.Suite(&bakerySuite{})

func (s *bakerySuite) TestRootKeyStore(c *gc.C) {
	backend, err := mgostore.NewBackend(s.Session.DB("bakery-test"))
	c.Assert(err, gc.Equals, nil)
	defer backend.Close()
	ctx := context.Background()
	rks := backend.BakeryRootKeyStore()

	key, id, err := rks.RootKey(ctx)
	c.Assert(err, gc.Equals, nil)

	key2, err := rks.Get(ctx, id)
	c.Assert(err, gc.Equals, nil)

	c.Assert(key2, jc.DeepEquals, key)
}
