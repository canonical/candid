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

type kvSuite struct {
	testing.IsolatedMgoSuite
	storetesting.KeyValueSuite
	backend store.Backend
}

var _ = gc.Suite(&kvSuite{})

func (s *kvSuite) SetUpSuite(c *gc.C) {
	s.IsolatedMgoSuite.SetUpSuite(c)
	s.KeyValueSuite.SetUpSuite(c)
}

func (s *kvSuite) TearDownSuite(c *gc.C) {
	s.KeyValueSuite.TearDownSuite(c)
	s.IsolatedMgoSuite.TearDownSuite(c)
}

func (s *kvSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.backend, err = mgostore.NewBackend(s.Session.DB("candid-test"))
	c.Assert(err, gc.Equals, nil)
	s.Store = s.backend.ProviderDataStore()
	s.KeyValueSuite.SetUpTest(c)
}

func (s *kvSuite) TearDownTest(c *gc.C) {
	s.KeyValueSuite.TearDownTest(c)
	s.backend.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}
