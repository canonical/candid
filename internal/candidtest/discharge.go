// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package candidtest provides suites and functions useful for testing the
// identity manager.
package candidtest

import (
	"net/url"
	"time"

	qt "github.com/frankban/quicktest"
	"golang.org/x/net/context"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	macaroon "gopkg.in/macaroon.v2"
)

// DischargeCreator represents a third party service
// that creates discharges addressed to Candid.
type DischargeCreator struct {
	ServerURL string

	Bakery *identchecker.Bakery

	bakeryKey *bakery.KeyPair
}

// NewDischargeCreator returns a DischargeCreator that
// creates third party caveats addressed to the given server,
// which must be serving the "discharger" API.
func NewDischargeCreator(server *Server) *DischargeCreator {
	bakeryKey, err := bakery.GenerateKey()
	if err != nil {
		panic(err)
	}
	return &DischargeCreator{
		ServerURL: server.URL,
		Bakery: identchecker.NewBakery(identchecker.BakeryParams{
			Locator:        server,
			Key:            bakeryKey,
			IdentityClient: server.AdminIdentityClient(),
			Location:       "discharge-test",
		}),
		bakeryKey: bakeryKey,
	}
}

// AssertDischarge checks that a macaroon can be discharged with
// interaction using the specified visitor.
func (s *DischargeCreator) AssertDischarge(c *qt.C, i httpbakery.Interactor) {
	ms, err := s.Discharge(c, "is-authenticated-user", BakeryClient(i))
	c.Assert(err, qt.Equals, nil)
	_, err = s.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Assert(err, qt.Equals, nil)
}

// Discharge attempts to perform a discharge of a new macaroon against
// this suites identity server using the given client and returns a
// macaroon slice containing a discharged macaroon or any error. The
// newly minted macaroon will have a third-party caveat addressed to the
// identity server with the given condition.
func (s *DischargeCreator) Discharge(c *qt.C, condition string, client *httpbakery.Client) (macaroon.Slice, error) {
	return client.DischargeAll(context.Background(), s.NewMacaroon(c, condition, identchecker.LoginOp))
}

// NewMacaroon creates a new macaroon with a third-party caveat addressed
// to the identity server which has the given condition.
func (s *DischargeCreator) NewMacaroon(c *qt.C, condition string, op bakery.Op) *bakery.Macaroon {
	m, err := s.Bakery.Oven.NewMacaroon(
		context.Background(),
		bakery.LatestVersion,
		[]checkers.Caveat{{
			Location:  s.ServerURL,
			Condition: condition,
		}, checkers.TimeBeforeCaveat(time.Now().Add(time.Minute))},
		op,
	)
	c.Assert(err, qt.Equals, nil)
	return m
}

// AssertMacaroon asserts that the given macaroon slice is valid for the
// given operation. If id is specified then the declared identity in the
// macaroon is checked to be the same as id.
func (s *DischargeCreator) AssertMacaroon(c *qt.C, ms macaroon.Slice, op bakery.Op, id string) {
	ui, err := s.Bakery.Checker.Auth(ms).Allow(context.Background(), op)
	c.Assert(err, qt.Equals, nil)
	if id == "" {
		return
	}
	c.Assert(ui.Identity.Id(), qt.Equals, id)
}

// A VisitorFunc converts a function to a httpbakery.LegacyInteractor.
type VisitorFunc func(*url.URL) error

// LegacyInteract implements httpbakery.LegacyInteractor.LegacyInteract.
func (f VisitorFunc) LegacyInteract(ctx context.Context, _ *httpbakery.Client, _ string, u *url.URL) error {
	return f(u)
}
