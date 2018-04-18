// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore_test

import (
	"github.com/juju/testing"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/mgostore"
	storetesting "github.com/CanonicalLtd/candid/store/testing"
)

type meetingSuite struct {
	testing.IsolatedMgoSuite
	storetesting.MeetingSuite
	backend store.Backend
}

var _ = gc.Suite(&meetingSuite{})

func (s *meetingSuite) SetUpSuite(c *gc.C) {
	s.IsolatedMgoSuite.SetUpSuite(c)
	s.MeetingSuite.SetUpSuite(c)
}

func (s *meetingSuite) TearDownSuite(c *gc.C) {
	s.MeetingSuite.TearDownSuite(c)
	s.IsolatedMgoSuite.TearDownSuite(c)
}

func (s *meetingSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.backend, err = mgostore.NewBackend(s.Session.DB("candid-test"))
	c.Assert(err, gc.Equals, nil)
	s.Store = s.backend.MeetingStore()
	s.PutAtTimeFunc = mgostore.PutAtTime
	s.MeetingSuite.SetUpTest(c)
}

func (s *meetingSuite) TearDownTest(c *gc.C) {
	s.MeetingSuite.TearDownTest(c)
	s.backend.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}
