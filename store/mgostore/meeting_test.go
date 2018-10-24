// Copyright 2015 Canonical Ltd.
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

type meetingSuite struct {
	storetesting.MeetingSuite
	db      *mgotest.Database
	backend store.Backend
}

var _ = gc.Suite(&meetingSuite{})

func (s *meetingSuite) SetUpTest(c *gc.C) {
	var err error
	s.db, err = mgotest.New()
	if errgo.Cause(err) == mgotest.ErrDisabled {
		c.Skip("mgotest disabled")
	}
	c.Assert(err, gc.Equals, nil)
	s.backend, err = mgostore.NewBackend(s.db.Database)
	c.Assert(err, gc.Equals, nil)
	s.Store = s.backend.MeetingStore()
	s.PutAtTimeFunc = mgostore.PutAtTime
	s.MeetingSuite.SetUpTest(c)
}

func (s *meetingSuite) TearDownTest(c *gc.C) {
	s.MeetingSuite.TearDownTest(c)
	if s.backend != nil {
		s.backend.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
}
