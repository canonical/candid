// Copyright 2017 Canonical Ltd.

package memstore_test

import (
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/memstore"
	"github.com/CanonicalLtd/blues-identity/store/testing"
)

type memstoreSuite struct {
	testing.StoreSuite
}

var _ = gc.Suite(&memstoreSuite{})

func (s *memstoreSuite) SetUpTest(c *gc.C) {
	s.Store = memstore.NewStore()
	s.StoreSuite.SetUpTest(c)
}
