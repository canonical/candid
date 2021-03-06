// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package httpauth_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/juju/aclstore/v2"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v3/bakery"
	"gopkg.in/macaroon-bakery.v3/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"github.com/canonical/candid/v2/internal/auth"
	"github.com/canonical/candid/v2/internal/auth/httpauth"
	"github.com/canonical/candid/v2/internal/candidtest"
	"github.com/canonical/candid/v2/params"
)

type authSuite struct {
	store      *candidtest.Store
	oven       *bakery.Oven
	aclManager *aclstore.Manager
}

func TestAuth(t *testing.T) {
	qtsuite.Run(qt.New(t), &authSuite{})
}

const identityLocation = "https://identity.test/id"

func (s *authSuite) Init(c *qt.C) {
	s.store = candidtest.NewStore()

	key, err := bakery.GenerateKey()
	c.Assert(err, qt.IsNil)
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
	s.aclManager, err = aclstore.NewManager(context.Background(), aclstore.Params{
		Store:             s.store.ACLStore,
		InitialAdminUsers: []string{auth.AdminUsername},
	})
	c.Assert(err, qt.IsNil)
}

func (s *authSuite) TestAuthorizeWithAdminCredentials(c *qt.C) {
	tests := []struct {
		about              string
		adminPassword      string
		header             http.Header
		expectErrorMessage string
	}{{
		about:         "good credentials",
		adminPassword: "open sesame",
		header: http.Header{
			"Authorization": []string{"Basic " + b64str("admin:open sesame")},
		},
	}, {
		about:         "bad username",
		adminPassword: "open sesame",
		header: http.Header{
			"Authorization": []string{"Basic " + b64str("xadmin:open sesame")},
		},
		expectErrorMessage: "could not determine identity: invalid credentials",
	}, {
		about:         "bad password",
		adminPassword: "open sesame",
		header: http.Header{
			"Authorization": []string{"Basic " + b64str("admin:open sesam")},
		},
		expectErrorMessage: "could not determine identity: invalid credentials",
	}, {
		about:         "empty password denies access",
		adminPassword: "",
		header: http.Header{
			"Authorization": []string{"Basic " + b64str("admin:")},
		},
		expectErrorMessage: "could not determine identity: invalid credentials",
	}}
	for _, test := range tests {
		c.Run(test.about, func(c *qt.C) {
			authorizer, err := auth.New(auth.Params{
				AdminPassword:    test.adminPassword,
				Location:         identityLocation,
				Store:            s.store.Store,
				MacaroonVerifier: s.oven,
				ACLManager:       s.aclManager,
			})
			c.Assert(err, qt.IsNil)
			err = authorizer.SetAdminPublicKey(context.Background(), &bakery.PublicKey{})
			c.Assert(err, qt.IsNil)
			httpAuthorizer := httpauth.New(s.oven, authorizer, 0)
			req, _ := http.NewRequest("GET", "/", nil)
			for attr, val := range test.header {
				req.Header[attr] = val
			}
			authInfo, err := httpAuthorizer.Auth(context.Background(), req, identchecker.LoginOp)
			if test.expectErrorMessage != "" {
				c.Assert(err, qt.ErrorMatches, test.expectErrorMessage)
				c.Assert(errgo.Cause(err), qt.Equals, params.ErrUnauthorized)
				return
			}
			c.Assert(err, qt.IsNil)
			c.Assert(authInfo.Identity.Id(), qt.Equals, auth.AdminUsername)
		})
	}
}

func (s *authSuite) TestAuthorizeMacaroonRequired(c *qt.C) {
	authorizer, err := auth.New(auth.Params{
		AdminPassword:    "open sesame",
		Location:         identityLocation,
		Store:            s.store.Store,
		MacaroonVerifier: s.oven,
		ACLManager:       s.aclManager,
	})
	httpAuthorizer := httpauth.New(s.oven, authorizer, 0)
	req, err := http.NewRequest("GET", "http://example.com/v1/test", nil)
	c.Assert(err, qt.IsNil)
	authInfo, err := httpAuthorizer.Auth(context.Background(), req, identchecker.LoginOp)
	c.Assert(err, qt.ErrorMatches, `macaroon discharge required: authentication required`)
	c.Assert(authInfo, qt.IsNil)
	derr, ok := errgo.Cause(err).(*httpbakery.Error)
	if !ok {
		c.Fatalf("error %#v is not httpbakery.Error", err)
	}
	c.Assert(derr.Info.CookieNameSuffix, qt.Equals, "candid")
	c.Assert(derr.Info.MacaroonPath, qt.Equals, "../")
	c.Assert(derr.Info.Macaroon, qt.Not(qt.IsNil))
}

func b64str(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
