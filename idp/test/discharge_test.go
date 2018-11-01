// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package test_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/test"
	"github.com/CanonicalLtd/candid/internal/discharger"
	"github.com/CanonicalLtd/candid/internal/identity"
	candidtest "github.com/CanonicalLtd/candid/internal/qtcandidtest"
)

type dischargeSuite struct {
	candid           *candidtest.Server
	dischargeCreator *candidtest.DischargeCreator
}

func TestDischarge(t *testing.T) {
	qtsuite.Run(qt.New(t), &dischargeSuite{})
}

func (s *dischargeSuite) Init(c *qt.C) {
	candidtest.LogTo(c)
	store := candidtest.NewStore()
	sp := store.ServerParams()
	sp.IdentityProviders = []idp.IdentityProvider{
		test.NewIdentityProvider(test.Params{
			Name: "test",
		}),
	}
	s.candid = candidtest.NewServer(c, sp, map[string]identity.NewAPIHandlerFunc{
		"discharger": discharger.NewAPIHandler,
	})
	s.dischargeCreator = candidtest.NewDischargeCreator(s.candid)
}

func (s *dischargeSuite) TestInteractiveDischarge(c *qt.C) {
	s.dischargeCreator.AssertDischarge(c, test.Interactor{
		User: &params.User{
			Username:   "test",
			ExternalID: "https://example.com/+id/test",
		},
	})
}

func (s *dischargeSuite) TestNonInteractiveDischarge(c *qt.C) {
	// TODO (mhilton) work out how to differentiate these.
	s.dischargeCreator.AssertDischarge(c, test.Interactor{
		User: &params.User{
			Username:   "test",
			ExternalID: "https://example.com/+id/test",
		},
	})
}
