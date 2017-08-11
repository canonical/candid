// Copyright 2015 Canonical Ltd.

// Package idp defines the API provided by all identity providers.
package idp

import (
	"html/template"
	"net/http"

	"golang.org/x/net/context"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"

	"github.com/CanonicalLtd/blues-identity/store"
)

// A LoginCompleter is used by the identity providers to finish login
// attempts.
type LoginCompleter interface {
	// Success is used by an identity provider to indicate that a
	// successful login has been completed for the given identity.
	Success(ctx context.Context, w http.ResponseWriter, req *http.Request, waitid string, id *store.Identity)

	// Failure is used by an identity provider to indicate that a
	// login attempt has failed with the specified error.
	Failure(ctx context.Context, w http.ResponseWriter, req *http.Request, waitid string, err error)
}

// InitParams are passed to the identity provider to initialise it.
type InitParams struct {
	// Store contains the identity store being used in the identity
	// server.
	Store store.Store

	// Oven contains an oven that may be used in the identity
	// provider to mint new macaroons.
	Oven *bakery.Oven

	// Key contains the identity server's public/private key pair.
	Key *bakery.KeyPair

	// URLPrefix contains the prefix of all requests to the Handle
	// method. The URL.Path parameter in the request passed to handle
	// will contain only the part after this prefix.
	URLPrefix string

	// LoginCompleter is the LoginCompleter that the identity
	// provider should use to complete login requests.
	LoginCompleter LoginCompleter

	// Template contains the templates loaded in the identity server.
	Template *template.Template
}

// IdentityProvider is the interface that is satisfied by all identity providers.
type IdentityProvider interface {
	// Name is the short name for the identity provider, this will
	// appear in urls.
	Name() string

	// Domain is the domain in which this identity provider will
	// create users.
	Domain() string

	// Description is a name for the identity provider used to show
	// end users.
	Description() string

	// Interactive indicates whether login is provided by the end
	// user interacting directly with the identity provider (usually
	// through a web browser).
	Interactive() bool

	// Init is used to perform any one time initialization tasks that
	// are needed for the identity provider. Init is called once by
	// the identity manager once it has determined the identity
	// providers final location, any initialization tasks that depend
	// on having access to the final URL, or the per identity
	// provider database should be performed here.
	Init(ctx context.Context, params InitParams) error

	// URL returns the URL to use to attempt a login with this
	// identity provider. If the identity provider is interactive
	// then the user will be automatically redirected to the URL.
	// Otherwise the URL is returned in the response to a
	// request for login methods.
	URL(waitid string) string

	// Handle handles any requests sent to the identity provider's
	// endpoints. The URL.Path in the request will contain only the
	// handler local path, that is the part after URLPrefix above.
	// The given request will have had ParseForm called.
	Handle(ctx context.Context, w http.ResponseWriter, req *http.Request)
}
