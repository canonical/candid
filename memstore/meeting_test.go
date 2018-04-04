// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package memstore_test

import (
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/memstore"
	"github.com/CanonicalLtd/blues-identity/store/testing"
)

type meetingSuite struct {
	testing.MeetingSuite
}

var _ = gc.Suite(&meetingSuite{})

func (s *meetingSuite) SetUpTest(c *gc.C) {
	s.Store = memstore.NewMeetingStore()
	s.PutAtTimeFunc = memstore.PutAtTime
	s.MeetingSuite.SetUpTest(c)
}
