// Copyright 2015 Canonical Ltd.

package idptest

import (
	"html/template"
	"net/http"

	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
	"github.com/CanonicalLtd/blues-identity/store"
)

// Suite provides a test suite that is helpful for testing identity
// providers.
type Suite struct {
	idmtest.StoreSuite

	// Template contains a template that will be passed in the
	// idp.InitParams.
	Template *template.Template

	// The following fields will be available after calling SetUpTest.

	// Ctx contains a context.Context that has been initialised with
	// the stores.
	Ctx context.Context

	// Oven contains a bakery.Oven that will be passed in the
	// idp.InitParams. Tests can use this to mint macaroons if
	// necessary.
	Oven *bakery.Oven

	loginCompleter    *loginCompleter
	closeStore        func()
	closeMeetingStore func()
}

func (s *Suite) SetUpTest(c *gc.C) {
	s.StoreSuite.SetUpTest(c)
	s.Ctx, s.closeStore = s.Store.Context(context.Background())
	s.Ctx, s.closeMeetingStore = s.MeetingStore.Context(s.Ctx)
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
	s.Oven = bakery.NewOven(bakery.OvenParams{
		Key:      key,
		Location: "idptest",
	})
}

func (s *Suite) TearDownTest(c *gc.C) {
	s.closeMeetingStore()
	s.closeStore()
	s.StoreSuite.TearDownTest(c)
}

// InitParams returns a completed InitParams that a test can use to pass
// to idp.Init.
func (s *Suite) InitParams(c *gc.C, prefix string) idp.InitParams {
	s.loginCompleter = &loginCompleter{
		c: c,
	}
	kv, err := s.ProviderDataStore.KeyValueStore(s.Ctx, "idptest")
	c.Assert(err, gc.Equals, nil)
	return idp.InitParams{
		Store:          s.Store,
		KeyValueStore:  kv,
		Oven:           s.Oven,
		Key:            s.Oven.Key(),
		URLPrefix:      prefix,
		LoginCompleter: s.loginCompleter,
		Template:       s.Template,
	}
}

// AssertLoginSuccess asserts that the login test has resulted in a
// successful login of the given user.
func (s *Suite) AssertLoginSuccess(c *gc.C, username string) {
	c.Assert(s.loginCompleter.called, gc.Equals, true)
	c.Assert(s.loginCompleter.id, gc.Not(gc.IsNil))
	c.Assert(s.loginCompleter.id.Username, gc.Equals, username)
}

// AssertLoginFailure asserts taht the login test has resulted in a
// failure with an error that matches the given regex.
func (s *Suite) AssertLoginFailureMatches(c *gc.C, regex string) {
	c.Assert(s.loginCompleter.called, gc.Equals, true)
	c.Assert(s.loginCompleter.err, gc.ErrorMatches, regex)
}

// AssertLoginNotComplete asserts that the login attempt has not yet
// completed.
func (s *Suite) AssertLoginNotComplete(c *gc.C) {
	c.Assert(s.loginCompleter.called, gc.Equals, false)
}

// AssertUser asserts that the specified user is stored in the store.
func (s *Suite) AssertUser(c *gc.C, id *store.Identity) {
	id1 := store.Identity{
		ProviderID: id.ProviderID,
		Username:   id.Username,
	}
	err := s.Store.Identity(s.Ctx, &id1)
	c.Assert(err, gc.Equals, nil)
	idmtest.AssertEqualIdentity(c, &id1, id)
}

type loginCompleter struct {
	c      *gc.C
	called bool
	waitid string
	id     *store.Identity
	err    error
}

func (l *loginCompleter) Success(_ context.Context, _ http.ResponseWriter, _ *http.Request, waitid string, id *store.Identity) {
	if l.called {
		l.c.Error("login completion method called more that once")
		return
	}
	l.called = true
	l.waitid = waitid
	l.id = id
}

func (l *loginCompleter) Failure(_ context.Context, _ http.ResponseWriter, _ *http.Request, waitid string, err error) {
	if l.called {
		l.c.Error("login completion method called more that once")
		return
	}
	l.called = true
	l.waitid = waitid
	l.err = err
}
