// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sqlstore_test

import (
	"github.com/juju/postgrestest"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/sqlstore"
	"github.com/CanonicalLtd/candid/store/testing"
)

type aclSuite struct {
	testing.ACLStoreSuite
	backend store.Backend
	pg      *postgrestest.DB
}

var _ = gc.Suite(&aclSuite{})

func (s *aclSuite) SetUpTest(c *gc.C) {
	var err error
	s.pg, err = postgrestest.New()
	if errgo.Cause(err) == postgrestest.ErrDisabled {
		c.Skip(err.Error())
		return
	}
	c.Assert(err, gc.Equals, nil)
	s.backend, err = sqlstore.NewBackend("postgres", s.pg.DB)
	c.Assert(err, gc.Equals, nil)
	s.Store = s.backend.ACLStore()
	s.ACLStoreSuite.SetUpTest(c)
}

func (s *aclSuite) TearDownTest(c *gc.C) {
	if s.Store != nil {
		s.ACLStoreSuite.TearDownTest(c)
	}
	if s.backend != nil {
		s.backend.Close()
	}
	if s.pg != nil {
		s.pg.Close()
	}
}
