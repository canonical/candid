// Copyright 2014 Canonical Ltd.

package httpauth_test

import (
	"net/http"

	"github.com/juju/idmclient/params"
	"github.com/juju/testing"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/internal/auth"
	"github.com/CanonicalLtd/blues-identity/internal/auth/httpauth"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

type authSuite struct {
	testing.IsolatedMgoSuite
	pool       *store.Pool
	oven       *bakery.Oven
	authorizer *httpauth.Authorizer
}

var _ = gc.Suite(&authSuite{})

const identityLocation = "https://identity.test/id"

func (s *authSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.pool, err = store.NewPool(
		s.Session.Copy().DB("idm-test"),
		store.StoreParams{},
	)
	c.Assert(err, gc.IsNil)
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	locator := bakery.NewThirdPartyStore()
	locator.AddInfo(identityLocation, bakery.ThirdPartyInfo{
		PublicKey: key.Public,
		Version:   bakery.LatestVersion,
	})
	s.oven = bakery.NewOven(bakery.OvenParams{
		Key:      key,
		Locator:  locator,
		Location: "identity",
	})
	authorizer := auth.New(auth.Params{
		AdminUsername:   "test-admin",
		AdminPassword:   "open sesame",
		Location:        identityLocation,
		MacaroonOpStore: s.oven,
	})
	s.authorizer = httpauth.New(s.oven, authorizer)
}

func (s *authSuite) TearDownTest(c *gc.C) {
	s.pool.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

func (s *authSuite) createIdentity(c *gc.C, doc *mongodoc.Identity) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	if doc.ExternalID != "" {
		err := store.UpsertUser(doc)
		c.Assert(err, gc.IsNil)
	} else {
		err := store.UpsertAgent(doc)
		c.Assert(err, gc.IsNil)
	}
}

func (s *authSuite) TestAuthorizeWithAdminCredentials(c *gc.C) {
	tests := []struct {
		about              string
		header             http.Header
		expectErrorMessage string
	}{{
		about: "good credentials",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1hZG1pbjpvcGVuIHNlc2FtZQ=="},
		},
	}, {
		about: "bad username",
		header: http.Header{
			"Authorization": []string{"Basic eGVzdC1hZG1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expectErrorMessage: "could not determine identity: invalid credentials",
	}, {
		about: "bad password",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1hZG1pbjpvcGVuIHNlc2FtAQ=="},
		},
		expectErrorMessage: "could not determine identity: invalid credentials",
	}}
	for i, test := range tests {
		c.Logf("test %d. %s", i, test.about)
		st := s.pool.GetNoLimit()
		defer s.pool.Put(st)
		req, _ := http.NewRequest("GET", "/", nil)
		for attr, val := range test.header {
			req.Header[attr] = val
		}
		authInfo, err := s.authorizer.Auth(context.Background(), req, bakery.LoginOp)
		if test.expectErrorMessage != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErrorMessage)
			c.Assert(errgo.Cause(err), gc.Equals, params.ErrUnauthorized)
			continue
		}
		c.Assert(err, gc.Equals, nil)
		c.Assert(authInfo.Identity, gc.Equals, auth.Identity(store.AdminUsername))
	}
}

func (s *authSuite) TestAuthorizeMacaroonRequired(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	req, err := http.NewRequest("GET", "http://example.com/v1/test", nil)
	c.Assert(err, gc.IsNil)
	authInfo, err := s.authorizer.Auth(context.Background(), req, bakery.LoginOp)
	c.Assert(err, gc.ErrorMatches, `macaroon discharge required: authentication required`)
	c.Assert(authInfo, gc.IsNil)
	c.Assert(errgo.Cause(err), gc.FitsTypeOf, (*httpbakery.Error)(nil))
	derr := errgo.Cause(err).(*httpbakery.Error)
	c.Assert(derr.Info.CookieNameSuffix, gc.Equals, "idm")
	c.Assert(derr.Info.MacaroonPath, gc.Equals, "../")
	c.Assert(derr.Info.Macaroon, gc.NotNil)
}
