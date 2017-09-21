// Copyright 2015 Canonical Ltd.

package test_test

import (
	"github.com/juju/idmclient/params"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/test"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
)

type dischargeSuite struct {
	idmtest.DischargeSuite
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
