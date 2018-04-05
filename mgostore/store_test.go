// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore_test

import (
	"github.com/juju/testing"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/mgostore"
	storetesting "github.com/CanonicalLtd/candid/store/testing"
)

type storeSuite struct {
	testing.IsolatedMgoSuite
	storetesting.StoreSuite
	db *mgostore.Database
}

var _ = gc.Suite(&storeSuite{})

func (s *storeSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.db, err = mgostore.NewDatabase(s.Session.DB("candid-test"))
	c.Assert(err, gc.Equals, nil)
	s.Store = s.db.Store()
	s.StoreSuite.SetUpTest(c)
}

func (s *storeSuite) TearDownTest(c *gc.C) {
	s.StoreSuite.TearDownTest(c)
	s.db.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}
