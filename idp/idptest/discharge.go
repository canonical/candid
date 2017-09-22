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
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"

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
	Locator bakery.ThirdPartyLocator

	serverKey *bakery.KeyPair
	srv       identity.HandlerCloser

	adminAgentKey *bakery.KeyPair
}

// SetUpTest creates a new identity server and serves it. It configures a
// number of clients for use in tests.
func (s *DischargeSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.serverKey, err = bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.adminAgentKey, err = bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	db := s.Session.DB("idptest")
	s.srv, err = identity.NewServer(db, identity.ServerParams{
		AuthUsername:        authUsername,
		AuthPassword:        authPassword,
		Key:                 s.serverKey,
		Launchpad:           "https://0.1.2.3/",
		Location:            DischargeLocation,
		MaxMgoSessions:      100,
		WaitTimeout:         time.Second,
		PrivateAddr:         "localhost",
		IdentityProviders:   s.IDPs,
		AdminAgentPublicKey: &s.adminAgentKey.Public,
		Template:            DefaultTemplate,
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
	bc := httpbakery.NewClient()
	bc.Client.Transport = s.RoundTripper
	bc.Key = s.adminAgentKey
	s.IDMClient, err = idmclient.New(idmclient.NewParams{
		BaseURL:       DischargeLocation,
		Client:        bc,
		AgentUsername: "admin@idm",
	})
	c.Assert(err, gc.IsNil)
	locator := bakery.NewThirdPartyStore()
	locator.AddInfo(DischargeLocation, bakery.ThirdPartyInfo{
		PublicKey: s.serverKey.Public,
		Version:   bakery.LatestVersion,
	})
	s.Locator = locator
}

func (s *DischargeSuite) TearDownTest(c *gc.C) {
	s.Server.Close()
	s.srv.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

// AssertDischarge asserts that a discharge sent through s.BakeryClient
// returns a macaroon that validates successfully against ch. If visitor is
// not nil then the clients WebPageVisitor will be set to visitor before
// discharging.
func (s *DischargeSuite) AssertDischarge(c *gc.C, visitor httpbakery.Visitor) {
	b, ms, err := s.Discharge(c, "is-authenticated-user", visitor)

	authInfo, err := b.Checker.Auth(ms).Allow(context.Background(), bakery.LoginOp)
	c.Assert(err, gc.IsNil)
	c.Assert(authInfo.Identity, gc.Not(gc.Equals), nil)
	c.Logf("identity: %#v", authInfo.Identity)
}

// Discharge creates a new Bakery and discharges the given third party caveat condition
// from a macaroon created in it. If visitor not nil then the clients WebPageVisitor will be
// set to visitor before discharging.
// It returns the Bakery instance and the discharged macaroon slice.
func (s *DischargeSuite) Discharge(c *gc.C, condition string, visitor httpbakery.Visitor) (*bakery.Bakery, macaroon.Slice, error) {
	ctx := context.TODO()
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	b := bakery.New(bakery.BakeryParams{
		Locator:        s.Locator,
		Key:            key,
		IdentityClient: IdentityClient{},
	})
	m, err := b.Oven.NewMacaroon(
		ctx,
		bakery.LatestVersion,
		time.Now().Add(time.Minute),
		[]checkers.Caveat{{
			Location:  DischargeLocation,
			Condition: condition,
		}},
		bakery.LoginOp,
	)
	if visitor != nil {
		defer testing.PatchValue(&s.BakeryClient.WebPageVisitor, visitor).Restore()
	}
	ms, err := s.BakeryClient.DischargeAll(ctx, m)
	return b, ms, err
}

type IdentityClient struct{}

func (c IdentityClient) IdentityFromContext(ctx context.Context) (bakery.Identity, []checkers.Caveat, error) {
	return nil, []checkers.Caveat{{
		Location:  DischargeLocation,
		Condition: "is-authenticated-user",
	}}, nil
}

func (c IdentityClient) DeclaredIdentity(ctx context.Context, declared map[string]string) (bakery.Identity, error) {
	username, ok := declared["username"]
	if !ok {
		return nil, errgo.Newf("no declared user")
	}
	return bakery.SimpleIdentity(username), nil
}

type VisitorFunc func(*url.URL) error

func (f VisitorFunc) VisitWebPage(ctx context.Context, _ *httpbakery.Client, m map[string]*url.URL) error {
	return f(m[httpbakery.UserInteractionMethod])
}
