// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package candidtest provides suites and functions useful for testing the
// identity manager.
package candidtest

import (
	"net/url"
	"time"

	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/CanonicalLtd/candid/internal/discharger"
	"github.com/CanonicalLtd/candid/internal/identity"
	"github.com/CanonicalLtd/candid/mgostore"
)

// A DischargeSuite is a test suite useful for testing discharges.
type DischargeSuite struct {
	StoreServerSuite

	Bakery *identchecker.Bakery

	bakeryKey *bakery.KeyPair
	db        *mgostore.Database
}

// SetUpTest creates a new identity server ready to perform discharges
// and serves it.
func (s *DischargeSuite) SetUpTest(c *gc.C) {
	s.Versions = map[string]identity.NewAPIHandlerFunc{
		"discharger": discharger.NewAPIHandler,
	}
	s.StoreServerSuite.SetUpTest(c)
	var err error
	s.bakeryKey, err = bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
	s.Bakery = identchecker.NewBakery(identchecker.BakeryParams{
		Locator:        s,
		Key:            s.bakeryKey,
		IdentityClient: s.AdminIdentityClient(c),
		Location:       "discharge-test",
	})
}

// AssertDischarge checks that a macaroon can be discharged with
// interaction using the specified visitor.
func (s *DischargeSuite) AssertDischarge(c *gc.C, i httpbakery.Interactor) {
	ms, err := s.Discharge(c, "is-authenticated-user", s.Client(i))
	c.Assert(err, gc.Equals, nil)
	_, err = s.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Assert(err, gc.Equals, nil)
}

// Discharge attempts to perform a discharge of a new macaroon against
// this suites identity server using the given client and returns a
// macaroon slice containing a discharged macaroon or any error. The
// newly minted macaroon will have a third-party caveat addressed to the
// identity server with the given condition.
func (s *DischargeSuite) Discharge(c *gc.C, condition string, client *httpbakery.Client) (macaroon.Slice, error) {
	return client.DischargeAll(s.Ctx, s.NewMacaroon(c, condition, identchecker.LoginOp))
}

// NewMacaroon creates a new macaroon with a third-party caveat addressed
// to the identity server which has the given condition.
func (s *DischargeSuite) NewMacaroon(c *gc.C, condition string, op bakery.Op) *bakery.Macaroon {
	m, err := s.Bakery.Oven.NewMacaroon(
		context.Background(),
		bakery.LatestVersion,
		[]checkers.Caveat{{
			Location:  s.URL,
			Condition: condition,
		}, checkers.TimeBeforeCaveat(time.Now().Add(time.Minute))},
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

// A VisitorFunc converts a function to a httpbakery.LegacyInteractor.
type VisitorFunc func(*url.URL) error

// VisitWebPage implements httpbakery.Visitor.VisitWebPage.
func (f VisitorFunc) LegacyInteract(ctx context.Context, _ *httpbakery.Client, _ string, u *url.URL) error {
	return f(u)
}
