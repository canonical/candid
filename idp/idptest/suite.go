// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package idptest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/juju/qthttptest"
	"github.com/juju/simplekv"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v3/bakery"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/idputil"
	"github.com/canonical/candid/idp/idputil/secret"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/params"
	"github.com/canonical/candid/store"
)

// Fixture provides a test fixture that is helpful for testing identity
// providers.
type Fixture struct {
	// Ctx holds a context appropriate for using
	// for store methods.
	Ctx context.Context

	// Codec contains a codec that will be passed in the idp.InitParams.
	Codec *secret.Codec

	// Oven contains a bakery.Oven that will be passed in the
	// idp.InitParams. Tests can use this to mint macaroons if
	// necessary.
	Oven *bakery.Oven

	// Store holds the store used by the fixture.
	Store *candidtest.Store

	// Template holds the template to use for generating pages
	Template *template.Template

	dischargeTokenCreator *dischargeTokenCreator
	visitCompleter        *visitCompleter
	kvStore               simplekv.Store
}

func NewFixture(c *qt.C, store *candidtest.Store) *Fixture {
	ctx, closeStore := store.Store.Context(context.Background())
	c.Cleanup(closeStore)

	ctx, closeMeetingStore := store.MeetingStore.Context(ctx)
	c.Cleanup(closeMeetingStore)

	key, err := bakery.GenerateKey()
	c.Assert(err, qt.IsNil)
	oven := bakery.NewOven(bakery.OvenParams{
		Key:      key,
		Location: "idptest",
	})
	kv, err := store.ProviderDataStore.KeyValueStore(ctx, "idptest")
	c.Assert(err, qt.IsNil)
	return &Fixture{
		Ctx:                   ctx,
		Codec:                 secret.NewCodec(key),
		Oven:                  oven,
		Store:                 store,
		Template:              candidtest.DefaultTemplate,
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
		Codec:                 s.Codec,
		URLPrefix:             prefix,
		DischargeTokenCreator: s.dischargeTokenCreator,
		VisitCompleter:        s.visitCompleter,
		Template:              s.Template,
	}
}

// LoginState creates a candid-login with the given login state.
func (s *Fixture) LoginState(c *qt.C, state idputil.LoginState) (*http.Cookie, string) {
	value, err := s.Codec.Encode(state)
	c.Assert(err, qt.IsNil)
	rawValue, err := base64.URLEncoding.DecodeString(value)
	c.Assert(err, qt.IsNil)
	hash := sha256.Sum256(rawValue)
	return &http.Cookie{
		Name:  idputil.LoginCookieName,
		Value: value,
	}, base64.RawURLEncoding.EncodeToString(hash[:])
}

// Client creates an HTTP client that will replace the given prefix with
// the given replacement in all request URLs. The client will also stop
// redirecting and return the last response when a request with the given
// stopPrefix is attempted.
func (s *Fixture) Client(c *qt.C, prefix, replacement, stopPrefix string) *http.Client {
	jar, err := cookiejar.New(nil)
	c.Assert(err, qt.IsNil)
	return &http.Client{
		Transport: qthttptest.URLRewritingTransport{
			MatchPrefix:  prefix,
			Replace:      replacement,
			RoundTripper: http.DefaultTransport,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), stopPrefix) {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Jar: jar,
	}
}

// ParseResponse parses a store.Identity from the given HTTP response.
func (s *Fixture) ParseResponse(c *qt.C, resp *http.Response) (*store.Identity, error) {
	switch resp.StatusCode {
	case http.StatusOK:
		buf, err := ioutil.ReadAll(resp.Body)
		c.Assert(err, qt.IsNil)
		parts := bytes.Split(buf, []byte("\n"))
		if len(parts) > 1 && len(parts[1]) > 0 {
			return nil, errgo.New(string(parts[1]))
		}
	case http.StatusSeeOther:
		ru, err := url.Parse(resp.Header.Get("Location"))
		c.Assert(err, qt.IsNil)
		rv := ru.Query()
		if msg := rv.Get("error"); msg != "" {
			if code := rv.Get("error_code"); code != "" {
				return nil, errgo.WithCausef(nil, params.ErrorCode(code), "%s", msg)
			}
			return nil, errgo.New(msg)
		}
		c.Assert(rv.Get("code"), qt.Equals, "6789")
		return s.visitCompleter.id, nil
	default:
		c.Fatalf("unexpected response type: %s", resp.Status)
	}
	return nil, nil
}

// DoInteractiveLogin performs a full interactive login cycle with the
// given IDP.
func (s *Fixture) DoInteractiveLogin(c *qt.C, idp idp.IdentityProvider, loginURL string, f func(*http.Client, *http.Response) (*http.Response, error)) (*store.Identity, error) {
	u, err := url.Parse(loginURL)
	c.Assert(err, qt.IsNil)
	hu := *u
	hu.Path = ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.ParseForm()
		idp.Handle(req.Context(), w, req)
	}))
	defer srv.Close()
	client := s.Client(c, hu.String(), srv.URL, "http://result.example.com")
	cookie, state := s.LoginState(c, idputil.LoginState{
		ReturnTo: "http://result.example.com/callback",
		State:    "1234",
		Expires:  time.Now().Add(10 * time.Minute),
	})
	client.Jar.SetCookies(&hu, []*http.Cookie{cookie})
	v := u.Query()
	v.Set("state", state)
	u.RawQuery = v.Encode()
	resp, err := client.Get(u.String())
	c.Assert(err, qt.IsNil)
	if f != nil {
		resp, err = f(client, resp)
		c.Assert(err, qt.IsNil)
	}
	defer resp.Body.Close()
	return s.ParseResponse(c, resp)
}

// AssertLoginSuccess asserts that the login test has resulted in a
// successful login of the given user.
func (s *Fixture) AssertLoginSuccess(c *qt.C, username string) {
	c.Assert(s.visitCompleter.called, qt.Equals, true)
	c.Check(s.visitCompleter.err, qt.Equals, nil)
	c.Assert(s.visitCompleter.id, qt.Not(qt.IsNil))
	c.Assert(s.visitCompleter.id.Username, qt.Equals, username)
}

// AssertLoginRedirectSuccess asserts that the given redirect URL is for
// a successful login of the given user.
func (s *Fixture) AssertLoginRedirectSuccess(c *qt.C, rurl, returnTo, state string, username string) {
	u, err := url.Parse(rurl)
	c.Assert(err, qt.IsNil)
	v := u.Query()
	u.RawQuery = ""
	c.Assert(u.String(), qt.Equals, returnTo)
	c.Assert(v.Get("state"), qt.Equals, state)
	c.Assert(v.Get("code"), qt.Equals, "6789")
	c.Assert(s.visitCompleter.id.Username, qt.Equals, username)
}

// AssertLoginFailureMatches asserts that the login test has resulted in a
// failure with an error that matches the given regex.
func (s *Fixture) AssertLoginFailureMatches(c *qt.C, regex string) {
	c.Assert(s.visitCompleter.called, qt.Equals, true)
	c.Assert(s.visitCompleter.err, qt.ErrorMatches, regex)
}

// AssertLoginRedirectFailureMatches asserts that the login test has resulted in a
// failure with an error that matches the given regex.
func (s *Fixture) AssertLoginRedirectFailureMatches(c *qt.C, rurl, returnTo, state, errorCode, regex string) {
	u, err := url.Parse(rurl)
	c.Assert(err, qt.IsNil)
	v := u.Query()
	u.RawQuery = ""
	c.Assert(u.String(), qt.Equals, returnTo)
	c.Assert(v.Get("state"), qt.Equals, state)
	c.Assert(v.Get("error_code"), qt.Equals, errorCode)
	c.Assert(v.Get("error"), qt.ErrorMatches, regex)
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
	id          *store.Identity
	err         error
}

func (l *visitCompleter) Success(_ context.Context, _ http.ResponseWriter, _ *http.Request, dischargeID string, id *store.Identity) {
	if l.called {
		l.c.Error("login completion method called more than once")
		return
	}
	l.called = true
	l.dischargeID = dischargeID
	l.id = id
}

func (l *visitCompleter) Failure(_ context.Context, _ http.ResponseWriter, _ *http.Request, dischargeID string, err error) {
	if l.called {
		l.c.Error("login completion method called more than once")
		return
	}
	l.called = true
	l.dischargeID = dischargeID
	l.err = err
}

// RedirectSuccess implements isp.VisitCompleter.RedirectSuccess.
func (l *visitCompleter) RedirectSuccess(_ context.Context, w http.ResponseWriter, req *http.Request, returnTo, state string, id *store.Identity) {
	if l.called {
		l.c.Error("login completion method called more than once")
		return
	}
	l.id = id
	u, err := url.Parse(returnTo)
	if err != nil {
		l.c.Error(err)
		return
	}
	v := u.Query()
	v.Set("state", state)
	v.Set("code", "6789")
	u.RawQuery = v.Encode()
	http.Redirect(w, req, u.String(), http.StatusSeeOther)
}

// RedirectFailure implements isp.VisitCompleter.RedirectFailure.
func (l *visitCompleter) RedirectFailure(_ context.Context, w http.ResponseWriter, req *http.Request, returnTo, state string, verr error) {
	if l.called {
		l.c.Error("login completion method called more than once")
		return
	}
	l.called = true

	u, err := url.Parse(returnTo)
	if err != nil {
		l.c.Error(err)
		return
	}
	v := u.Query()
	v.Set("state", state)
	v.Set("error", verr.Error())
	if ec, ok := errgo.Cause(verr).(errorCoder); ok {
		v.Set("error_code", string(ec.ErrorCode()))
	}
	u.RawQuery = v.Encode()
	http.Redirect(w, req, u.String(), http.StatusSeeOther)
}

func (l *visitCompleter) RedirectMFA(ctx context.Context, w http.ResponseWriter, req *http.Request, requireMFA bool, returnTo, returnToState, state string, id *store.Identity) {
	// NOTE: mfa is currently not tested via unit-tests.
	l.RedirectSuccess(ctx, w, req, returnTo, returnToState, id)
}

func (f *Fixture) Reset() {
	f.visitCompleter.called = false
	f.visitCompleter.dischargeID = ""
	f.visitCompleter.id = nil
	f.visitCompleter.err = nil
}

type errorCoder interface {
	ErrorCode() params.ErrorCode
}

type dischargeTokenCreator struct{}

func (d *dischargeTokenCreator) DischargeToken(_ context.Context, id *store.Identity) (*httpbakery.DischargeToken, error) {
	return &httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte(id.Username),
	}, nil
}
