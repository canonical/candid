// Copyright 2017 Canonical Ltd.

// Package idmtest provides suites and functions useful for testing the
// identity manager.
package idmtest

import (
	"net/url"
	"time"

	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	macaroon "gopkg.in/macaroon.v2-unstable"

	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/v1"
	"github.com/CanonicalLtd/blues-identity/mgostore"
)

// A DischargeSuite is a test suite useful for testing discharges.
type DischargeSuite struct {
	StoreServerSuite

	Bakery *bakery.Bakery

	bakeryKey *bakery.KeyPair
	db        *mgostore.Database
}

// SetUpTest creates a new identity server ready to perform discharges
// and serves it.
func (s *DischargeSuite) SetUpTest(c *gc.C) {
	s.Versions = map[string]identity.NewAPIHandlerFunc{
		"v1": v1.NewAPIHandler,
	}
	s.StoreServerSuite.SetUpTest(c)
	var err error
	s.bakeryKey, err = bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
	s.Bakery = bakery.New(bakery.BakeryParams{
		Locator:        s,
		Key:            s.bakeryKey,
		IdentityClient: s.AdminIdentityClient(c),
		Location:       "discharge-test",
	})
}

// AssertDischarge checks that a macaroon can be discharged with
// interaction using the specified visitor.
func (s *DischargeSuite) AssertDischarge(c *gc.C, v httpbakery.Visitor) {
	ms, err := s.Discharge(c, "is-authenticated-user", s.Client(v))
	c.Assert(err, gc.Equals, nil)
	_, err = s.Bakery.Checker.Auth(ms).Allow(context.Background(), bakery.LoginOp)
	c.Assert(err, gc.Equals, nil)
}

// Discharge attempts to perform a discharge of a new macaroon against
// this suites identity server using the given client and returns a
// macaroon slice containing a discharged macaroon or any error. The
// newly minted macaroon will have a third-party caveat addressed to the
// identity server with the given condition.
func (s *DischargeSuite) Discharge(c *gc.C, condition string, client *httpbakery.Client) (macaroon.Slice, error) {
	return client.DischargeAll(s.Ctx, s.NewMacaroon(c, condition, bakery.LoginOp))
}

// NewMacaroon creates a new macaroon with a third-party caveat addressed
// to the identity server which has the given condition.
func (s *DischargeSuite) NewMacaroon(c *gc.C, condition string, op bakery.Op) *bakery.Macaroon {
	m, err := s.Bakery.Oven.NewMacaroon(
		context.Background(),
		bakery.LatestVersion,
		time.Now().Add(time.Minute),
		[]checkers.Caveat{{
			Location:  s.URL,
			Condition: condition,
		}},
		op,
	)
	c.Assert(err, gc.Equals, nil)
	return m
}

// AssertMacaroon asserts that the given macaroon slice is valid for the
// given operation. If id is specified then the declared identity in the
// macaroon is checked to be the same as id.
func (s *DischargeSuite) AssertMacaroon(c *gc.C, ms macaroon.Slice, op bakery.Op, id string) {
	ui, err := s.Bakery.Checker.Auth(ms).Allow(context.Background(), op)
	c.Assert(err, gc.Equals, nil)
	if id == "" {
		return
	}
	c.Assert(ui.Identity.Id(), gc.Equals, id)
}

// A VisitorFunc converts a function to a httpbakery.Visitor.
type VisitorFunc func(*url.URL) error

// VisitWebPage implements httpbakery.Visitor.VisitWebPage.
func (f VisitorFunc) VisitWebPage(ctx context.Context, _ *httpbakery.Client, m map[string]*url.URL) error {
	return f(m[httpbakery.UserInteractionMethod])
}
