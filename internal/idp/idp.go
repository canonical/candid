// Copyright 2015 Canonical Ltd.

package idp

import (
	"fmt"

	"github.com/juju/httprequest"
	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

var logger = loggo.GetLogger("identity.internal.idp")

// Context provides the identity provider methods with the context in
// which they are being run.
type Context interface {
	// Store gets a identity.Store object that can be used with the current handler.
	Store() *store.Store

	// IDPURL generates a url addressed to the identity provider requesting the URL.
	IDPURL(path string) string

	// RequestURL gets the original URL used to initiate the request
	RequestURL() string

	// LoginSuccess completes a login request successfully.
	LoginSuccess(macaroon.Slice) bool

	// LoginFailure fails a login request.
	LoginFailure(error)

	// Params gets the params for the current request.
	Params() httprequest.Params
}

// loginIdentity creates an identity macaroon for the specified identity
// and completes the login process.
func loginIdentity(c Context, identity *mongodoc.Identity) {
	// We provide the user with a macaroon that they can use later
	// to prove to us that they have logged in. The macaroon is valid
	// for any operation that that user is allowed to perform.

	// TODO add expiry date and maybe more first party caveats to this.
	m, err := c.Store().Service.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", identity.Username),
	})
	if err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot create macaroon"))
		return
	}
	if c.LoginSuccess(macaroon.Slice{m}) {
		fmt.Fprintf(c.Params().Response, "login successful as user %s\n", identity.Username)
	}
}
