// Copyright 2015 Canonical Ltd.

package test_test

import (
	"github.com/juju/idmclient/params"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/test"
)

type dischargeSuite struct {
	idptest.DischargeSuite
	visitor test.Visitor
}

var _ = gc.Suite(&dischargeSuite{})

func (s *dischargeSuite) SetUpTest(c *gc.C) {
	s.IDPs = []idp.IdentityProvider{
		test.NewIdentityProvider(test.Params{
			Name: "test",
		}),
	}
	s.DischargeSuite.SetUpTest(c)
	s.visitor = test.Visitor{
		User: &params.User{
			Username:   "test",
			ExternalID: "https://example.com/+id/test",
		},
	}
}

func (s *dischargeSuite) TestInteractiveDischarge(c *gc.C) {
	s.AssertDischarge(c, s.visitor)
}

func (s *dischargeSuite) TestNonInteractiveDischarge(c *gc.C) {
	s.AssertDischarge(c, httpbakery.NewMultiVisitor(s.visitor))
}
