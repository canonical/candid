// Copyright 2017 Canonical Ltd.

package mgostore_test

import (
	"github.com/juju/testing"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/mgostore"
	storetesting "github.com/CanonicalLtd/blues-identity/store/testing"
)

type kvSuite struct {
	testing.IsolatedMgoSuite
	storetesting.KeyValueSuite
	db *mgostore.Database
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
	s.db, err = mgostore.NewDatabase(s.Session.DB("idm-test"))
	c.Assert(err, gc.Equals, nil)
	s.Store = s.db.ProviderDataStore()
	s.KeyValueSuite.SetUpTest(c)
}

func (s *kvSuite) TearDownTest(c *gc.C) {
	s.KeyValueSuite.TearDownTest(c)
	s.db.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}
