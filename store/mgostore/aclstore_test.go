// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore_test

import (
	"github.com/juju/testing"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/mgostore"
	storetesting "github.com/CanonicalLtd/candid/store/testing"
)

type aclSuite struct {
	testing.IsolatedMgoSuite
	storetesting.ACLStoreSuite
	backend store.Backend
}

var _ = gc.Suite(&aclSuite{})

func (s *aclSuite) SetUpSuite(c *gc.C) {
	s.IsolatedMgoSuite.SetUpSuite(c)
	s.ACLStoreSuite.SetUpSuite(c)
}

func (s *aclSuite) TearDownSuite(c *gc.C) {
	s.ACLStoreSuite.TearDownSuite(c)
	s.IsolatedMgoSuite.TearDownSuite(c)
}

func (s *aclSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.backend, err = mgostore.NewBackend(s.Session.DB("acl-test"))
	c.Assert(err, gc.Equals, nil)
	s.Store = s.backend.ACLStore()
	s.ACLStoreSuite.SetUpTest(c)
}

func (s *aclSuite) TearDownTest(c *gc.C) {
	s.ACLStoreSuite.TearDownTest(c)
	if s.backend != nil {
		s.backend.Close()
	}
	s.IsolatedMgoSuite.TearDownTest(c)
}
