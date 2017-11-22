// Copyright 2014 Canonical Ltd.

package httpauth_test

import (
	"net/http"

	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/idmclient.v1/params"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/blues-identity/internal/auth"
	"github.com/CanonicalLtd/blues-identity/internal/auth/httpauth"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
)

type authSuite struct {
	idmtest.StoreSuite
	oven       *bakery.Oven
	auth       *auth.Authorizer
	authorizer *httpauth.Authorizer
}

var _ = gc.Suite(&authSuite{})

const identityLocation = "https://identity.test/id"

func (s *authSuite) SetUpTest(c *gc.C) {
	s.StoreSuite.SetUpTest(c)
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
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
	s.auth = auth.New(auth.Params{
		AdminUsername:    "test-admin",
		AdminPassword:    "open sesame",
		Location:         identityLocation,
		Store:            s.Store,
		MacaroonVerifier: s.oven,
	})
	s.authorizer = httpauth.New(s.oven, s.auth)
}

func (s *authSuite) TearDownTest(c *gc.C) {
	s.StoreSuite.TearDownTest(c)
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
		req, _ := http.NewRequest("GET", "/", nil)
		for attr, val := range test.header {
			req.Header[attr] = val
		}
		authInfo, err := s.authorizer.Auth(context.Background(), req, identchecker.LoginOp)
		if test.expectErrorMessage != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErrorMessage)
			c.Assert(errgo.Cause(err), gc.Equals, params.ErrUnauthorized)
			continue
		}
		c.Assert(err, gc.Equals, nil)
		c.Assert(authInfo.Identity.Id(), gc.Equals, auth.AdminUsername)
	}
}

func (s *authSuite) TestAuthorizeMacaroonRequired(c *gc.C) {
	req, err := http.NewRequest("GET", "http://example.com/v1/test", nil)
	c.Assert(err, gc.IsNil)
	authInfo, err := s.authorizer.Auth(context.Background(), req, identchecker.LoginOp)
	c.Assert(err, gc.ErrorMatches, `macaroon discharge required: authentication required`)
	c.Assert(authInfo, gc.IsNil)
	c.Assert(errgo.Cause(err), gc.FitsTypeOf, (*httpbakery.Error)(nil))
	derr := errgo.Cause(err).(*httpbakery.Error)
	c.Assert(derr.Info.CookieNameSuffix, gc.Equals, "idm")
	c.Assert(derr.Info.MacaroonPath, gc.Equals, "../")
	c.Assert(derr.Info.Macaroon, gc.NotNil)
}
