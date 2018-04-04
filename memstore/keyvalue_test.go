// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package memstore_test

import (
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/memstore"
	"github.com/CanonicalLtd/blues-identity/store/testing"
)

type keyvalueSuite struct {
	testing.KeyValueSuite
}

var _ = gc.Suite(&keyvalueSuite{})

func (s *keyvalueSuite) SetUpTest(c *gc.C) {
	s.Store = memstore.NewProviderDataStore()
	s.KeyValueSuite.SetUpTest(c)
}
