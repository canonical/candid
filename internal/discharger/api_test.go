// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger_test

import (
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/discharger"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
)

var versions = map[string]identity.NewAPIHandlerFunc{
	"discharger": discharger.NewAPIHandler,
}

type apiSuite struct {
	idmtest.StoreServerSuite
}

func (s *apiSuite) SetUpTest(c *gc.C) {
	s.Versions = versions
	s.StoreServerSuite.SetUpTest(c)
}
