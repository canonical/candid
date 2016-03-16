// Copyright 2015 Canonical Ltd.

package idptest

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient"
	"github.com/juju/testing"
	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity"
	"github.com/CanonicalLtd/blues-identity/idp"
)

const (
	authUsername = "admin"
	authPassword = "password"

	// DischargeLocation is the location to which third party
	// discharges should be addressed.
	DischargeLocation = "https://idp.test"
)

// DischargeSuite provides a test suite that is helpful for testing
// identity provider discharges.
type DischargeSuite struct {
	testing.IsolatedMgoSuite

	// IDPs contains a list of IDPs to include in the identity
	// server. Test suites should set this list before calling
	// SetUpTest.
	IDPs []idp.IdentityProvider

	// The following members will become available once SetUpTest has
	// been called.

	// Server contains the httptest.Server instance
	Server *httptest.Server

	// RoundTripper contains an http.RoundTripper that can be used to
	// communicate with the test identity server.
	RoundTripper http.RoundTripper

	// HTTPClient contains an http.Client that can be used to
	// communicate with the test identity server.
	HTTPClient *http.Client

	// BakeryClient contains an httpbakery.Client that can be used to
	// communicate with the test identity server.
	BakeryClient *httpbakery.Client

	// HTTPRequestClient contains an httprequest.Client that can be
	// used to communicate with the test identity server.
	HTTPRequestClient *httprequest.Client

	// IDMClient contains an idmclient.Client that can be used to
	// communicate with the test identity server.
	IDMClient *idmclient.Client

	// Locator contains a bakery.PublicKeyLocator that can locate the
	// public key for DischargeLocation.
	Locator bakery.PublicKeyLocator

	serverKey *bakery.KeyPair
	srv       identity.HandlerCloser
}

// SetUpTest creates a new identity server and serves it. It configures a
// number of clients for use in tests.
func (s *DischargeSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.serverKey, err = bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	db := s.Session.DB("idptest")
	s.srv, err = identity.NewServer(db, identity.ServerParams{
		AuthUsername:      authUsername,
		AuthPassword:      authPassword,
		Key:               s.serverKey,
		Launchpad:         lpad.Production,
		Location:          DischargeLocation,
		MaxMgoSessions:    100,
		RequestTimeout:    time.Second,
		PrivateAddr:       "localhost",
		IdentityProviders: s.IDPs,
	}, identity.V1)
	c.Assert(err, gc.IsNil)
	s.Server = httptest.NewServer(s.srv)
	s.RoundTripper = &httptesting.URLRewritingTransport{
		MatchPrefix:  DischargeLocation,
		Replace:      s.Server.URL,
		RoundTripper: http.DefaultTransport,
	}
	s.BakeryClient = httpbakery.NewClient()
	s.BakeryClient.Client.Transport = s.RoundTripper
	s.HTTPClient = s.BakeryClient.Client
	s.HTTPRequestClient = &httprequest.Client{
		Doer: s.BakeryClient,
	}
	s.IDMClient = idmclient.New(idmclient.NewParams{
		BaseURL:      s.Server.URL,
		Client:       s.BakeryClient,
		AuthUsername: authUsername,
		AuthPassword: authPassword,
	})
	s.Locator = bakery.PublicKeyLocatorMap{
		DischargeLocation: &s.serverKey.Public,
	}
}

func (s *DischargeSuite) TearDownTest(c *gc.C) {
	s.Server.Close()
	s.srv.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

// AssertDischarge asserts that a discharge sent through s.BakeryClient
// returns a macaroon that validates successfully against ch. If visit is
// not nil the n s.BakeryClient.VisitWebPage will be set to visit before
// discharging.
func (s *DischargeSuite) AssertDischarge(c *gc.C, visit func(*url.URL) error, ch checkers.Checker) {
	b, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.Locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := b.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  DischargeLocation,
		Condition: "is-authenticated-user",
	}})
	c.Assert(err, gc.IsNil)
	if visit != nil {
		s.BakeryClient.VisitWebPage = visit
	}
	ms, err := s.BakeryClient.DischargeAll(m)
	c.Assert(err, gc.IsNil)
	declared := checkers.InferDeclared(ms)
	err = b.Check(ms, checkers.New(
		declared,
		ch,
	))
	c.Assert(err, gc.IsNil)
}
