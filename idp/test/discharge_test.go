// Copyright 2015 Canonical Ltd.

package test_test

import (
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/test"
	"github.com/CanonicalLtd/blues-identity/params"
)

type dischargeSuite struct {
	idptest.DischargeSuite
	visitor test.WebPageVisitor
}

var _ = gc.Suite(&dischargeSuite{})

func (s *dischargeSuite) SetUpTest(c *gc.C) {
	s.IDPs = []idp.IdentityProvider{
		test.IdentityProvider,
	}
	s.DischargeSuite.SetUpTest(c)
	s.visitor = test.WebPageVisitor{
		Client: s.HTTPRequestClient,
		User: &params.User{
			Username:   "test",
			ExternalID: "https://example.com/+id/test",
		},
	}
}

func (s *dischargeSuite) TestInteractiveDischarge(c *gc.C) {
	s.AssertDischarge(c, s.visitor.Interactive, checkers.New(
		checkers.TimeBefore,
	))
}

func (s *dischargeSuite) TestNonInteractiveDischarge(c *gc.C) {
	s.AssertDischarge(c, s.visitor.NonInteractive, checkers.New(
		checkers.TimeBefore,
	))
}
