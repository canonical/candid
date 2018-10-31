// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package idptest

import (
	"net/http"

	qt "github.com/frankban/quicktest"
	"golang.org/x/net/context"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/candid/idp"
	qtcandidtest "github.com/CanonicalLtd/candid/internal/qtcandidtest"
	"github.com/CanonicalLtd/candid/store"
	"github.com/juju/simplekv"
)

// Fixture provides a test fixture that is helpful for testing identity
// providers.
type Fixture struct {
	// Ctx holds a context appropriate for using
	// for store methods.
	Ctx context.Context

	// Oven contains a bakery.Oven that will be passed in the
	// idp.InitParams. Tests can use this to mint macaroons if
	// necessary.
	Oven *bakery.Oven

	// Store holds the store used by the fixture.
	Store *qtcandidtest.Store

	dischargeTokenCreator *dischargeTokenCreator
	visitCompleter        *visitCompleter
	kvStore               simplekv.Store
}

func NewFixture(c *qt.C, store *qtcandidtest.Store) *Fixture {
	ctx, closeStore := store.Store.Context(context.Background())
	c.Defer(closeStore)

	ctx, closeMeetingStore := store.MeetingStore.Context(ctx)
	c.Defer(closeMeetingStore)

	key, err := bakery.GenerateKey()
	c.Assert(err, qt.Equals, nil)
	oven := bakery.NewOven(bakery.OvenParams{
		Key:      key,
		Location: "idptest",
	})
	kv, err := store.ProviderDataStore.KeyValueStore(ctx, "idptest")
	c.Assert(err, qt.Equals, nil)
	return &Fixture{
		Ctx:   ctx,
		Oven:  oven,
		Store: store,
		dischargeTokenCreator: &dischargeTokenCreator{},
		visitCompleter: &visitCompleter{
			c: c,
		},
		kvStore: kv,
	}
}

// InitParams returns a completed InitParams that a test can use to pass
// to idp.Init.
func (s *Fixture) InitParams(c *qt.C, prefix string) idp.InitParams {
	return idp.InitParams{
		Store:                 s.Store.Store,
		KeyValueStore:         s.kvStore,
		Oven:                  s.Oven,
		Key:                   s.Oven.Key(),
		URLPrefix:             prefix,
		DischargeTokenCreator: s.dischargeTokenCreator,
		VisitCompleter:        s.visitCompleter,
	}
}

// AssertLoginSuccess asserts that the login test has resulted in a
// successful login of the given user.
func (s *Fixture) AssertLoginSuccess(c *qt.C, username string) {
	c.Assert(s.visitCompleter.called, qt.Equals, true)
	c.Check(s.visitCompleter.err, qt.Equals, nil)
	c.Assert(s.visitCompleter.id, qt.Not(qt.IsNil))
	c.Assert(s.visitCompleter.id.Username, qt.Equals, username)
}

// AssertLoginFailure asserts taht the login test has resulted in a
// failure with an error that matches the given regex.
func (s *Fixture) AssertLoginFailureMatches(c *qt.C, regex string) {
	c.Assert(s.visitCompleter.called, qt.Equals, true)
	c.Assert(s.visitCompleter.err, qt.ErrorMatches, regex)
}

// AssertLoginNotComplete asserts that the login attempt has not yet
// completed.
func (s *Fixture) AssertLoginNotComplete(c *qt.C) {
	c.Assert(s.visitCompleter.called, qt.Equals, false)
}

type visitCompleter struct {
	c           *qt.C
	called      bool
	dischargeID string
	returnTo    string
	state       string
	id          *store.Identity
	err         error
}

func (l *visitCompleter) Success(_ context.Context, _ http.ResponseWriter, _ *http.Request, dischargeID string, id *store.Identity) {
	if l.called {
		l.c.Error("login completion method called more that once")
		return
	}
	l.called = true
	l.dischargeID = dischargeID
	l.id = id
}

func (l *visitCompleter) Failure(_ context.Context, _ http.ResponseWriter, _ *http.Request, dischargeID string, err error) {
	if l.called {
		l.c.Error("login completion method called more that once")
		return
	}
	l.called = true
	l.dischargeID = dischargeID
	l.err = err
}

func (l *visitCompleter) RedirectSuccess(_ context.Context, _ http.ResponseWriter, _ *http.Request, returnTo, state string, id *store.Identity) {
	if l.called {
		l.c.Error("login completion method called more that once")
		return
	}
	l.called = true
	l.returnTo = returnTo
	l.state = state
	l.id = id
}

func (l *visitCompleter) RedirectFailure(_ context.Context, _ http.ResponseWriter, _ *http.Request, returnTo, state string, err error) {
	if l.called {
		l.c.Error("login completion method called more that once")
		return
	}
	l.called = true
	l.returnTo = returnTo
	l.state = state
	l.err = err
}

type dischargeTokenCreator struct{}

func (d *dischargeTokenCreator) DischargeToken(_ context.Context, id *store.Identity) (*httpbakery.DischargeToken, error) {
	return &httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte(id.Username),
	}, nil
}
