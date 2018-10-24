// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore_test

import (
	"github.com/juju/mgotest"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/mgostore"
	storetesting "github.com/CanonicalLtd/candid/store/testing"
)

type aclSuite struct {
	storetesting.ACLStoreSuite
	db      *mgotest.Database
	backend store.Backend
}

var _ = gc.Suite(&aclSuite{})

func (s *aclSuite) SetUpTest(c *gc.C) {
	var err error
	s.db, err = mgotest.New()
	if errgo.Cause(err) == mgotest.ErrDisabled {
		c.Skip("mgotest disabled")
	}
	c.Assert(err, gc.Equals, nil)
	s.backend, err = mgostore.NewBackend(s.db.Database)
	c.Assert(err, gc.Equals, nil)
	s.Store = s.backend.ACLStore()
	s.ACLStoreSuite.SetUpTest(c)
}

func (s *aclSuite) TearDownTest(c *gc.C) {
	s.ACLStoreSuite.TearDownTest(c)
	if s.backend != nil {
		s.backend.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
}
