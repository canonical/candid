// Copyright 2017 Canonical Ltd.

package mgostore_test

import (
	"time"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/mgorootkeystore"

	"github.com/CanonicalLtd/blues-identity/mgostore"
)

type bakerySuite struct {
	testing.IsolatedMgoSuite
}

var _ = gc.Suite(&bakerySuite{})

func (s *meetingSuite) TestRootKeyStore(c *gc.C) {
	db, err := mgostore.NewDatabase(s.Session.DB("bakery-test"))
	c.Assert(err, gc.Equals, nil)
	defer db.Close()
	ctx := context.Background()
	rks := db.BakeryRootKeyStore(mgorootkeystore.Policy{
		ExpiryDuration: time.Minute,
	})

	key, id, err := rks.RootKey(ctx)
	c.Assert(err, gc.Equals, nil)

	key2, err := rks.Get(ctx, id)
	c.Assert(err, gc.Equals, nil)

	c.Assert(key2, jc.DeepEquals, key)
}
