// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package test_test

import (
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/test"
	"github.com/CanonicalLtd/candid/internal/candidtest"
)

type dischargeSuite struct {
	candidtest.DischargeSuite
	interactor test.Interactor
}

var _ = gc.Suite(&dischargeSuite{})

func (s *dischargeSuite) SetUpTest(c *gc.C) {
	s.Params.IdentityProviders = []idp.IdentityProvider{
		test.NewIdentityProvider(test.Params{
			Name: "test",
		}),
	}
	s.DischargeSuite.SetUpTest(c)
	s.interactor = test.Interactor{
		User: &params.User{
			Username:   "test",
			ExternalID: "https://example.com/+id/test",
		},
	}
}

func (s *dischargeSuite) TestInteractiveDischarge(c *gc.C) {
	s.AssertDischarge(c, s.interactor)
}

func (s *dischargeSuite) TestNonInteractiveDischarge(c *gc.C) {
	// TODO (mhilton) work out how to differentiate these.
	s.AssertDischarge(c, s.interactor)
}
