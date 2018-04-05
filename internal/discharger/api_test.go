// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger_test

import (
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/internal/candidtest"
	"github.com/CanonicalLtd/candid/internal/discharger"
	"github.com/CanonicalLtd/candid/internal/identity"
)

var versions = map[string]identity.NewAPIHandlerFunc{
	"discharger": discharger.NewAPIHandler,
}

type apiSuite struct {
	candidtest.StoreServerSuite
}

func (s *apiSuite) SetUpTest(c *gc.C) {
	s.Versions = versions
	s.StoreServerSuite.SetUpTest(c)
}
