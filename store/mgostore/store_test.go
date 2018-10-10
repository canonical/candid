// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore_test

import (
	"github.com/juju/testing"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/mgostore"
	storetesting "github.com/CanonicalLtd/candid/store/testing"
)

type mgostoreSuite struct {
	testing.IsolatedMgoSuite
	storetesting.StoreSuite
	backend store.Backend
}

var _ = gc.Suite(&mgostoreSuite{})

func (s *mgostoreSuite) SetUpSuite(c *gc.C) {
	s.IsolatedMgoSuite.SetUpSuite(c)
	s.StoreSuite.SetUpSuite(c)
}

func (s *mgostoreSuite) TearDownSuite(c *gc.C) {
	s.StoreSuite.TearDownSuite(c)
	s.IsolatedMgoSuite.TearDownSuite(c)
}

func (s *mgostoreSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.backend, err = mgostore.NewBackend(s.Session.DB("candid-test"))
	c.Assert(err, gc.Equals, nil)
	s.Store = s.backend.Store()
	s.StoreSuite.SetUpTest(c)
}

func (s *mgostoreSuite) TearDownTest(c *gc.C) {
	s.StoreSuite.TearDownTest(c)
	s.backend.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}
