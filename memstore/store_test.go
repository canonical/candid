// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package memstore_test

import (
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/memstore"
	"github.com/CanonicalLtd/candid/store/testing"
)

type memstoreSuite struct {
	testing.StoreSuite
}

var _ = gc.Suite(&memstoreSuite{})

func (s *memstoreSuite) SetUpTest(c *gc.C) {
	s.Store = memstore.NewStore()
	s.StoreSuite.SetUpTest(c)
}
