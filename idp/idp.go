// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package idp defines the API provided by all identity providers.
package idp

import (
	"context"
	"html/template"
	"net/http"

	"github.com/juju/simplekv"
	"gopkg.in/macaroon-bakery.v3/bakery"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"github.com/canonical/candid/idp/idputil/secret"
	"github.com/canonical/candid/store"
)

// A DischargeTokenCreator is used by the identity providers to create a
// new httpbakery.DischargeToken for authenticated identity.
type DischargeTokenCreator interface {
	// DischargeToken creates a new httpbakery.DischargeToken for the
	// given identity.
	DischargeToken(ctx context.Context, id *store.Identity) (*httpbakery.DischargeToken, error)
}

// A VisitCompleter is used by the identity providers to finish login
// visit attempts.
type VisitCompleter interface {
	// Success is used by an identity provider to indicate that a
	// successful login has been completed for the given identity.
	Success(ctx context.Context, w http.ResponseWriter, req *http.Request, dischargeID string, id *store.Identity)

	// Failure is used by an identity provider to indicate that a
	// login attempt has failed with the specified error.
	Failure(ctx context.Context, w http.ResponseWriter, req *http.Request, dischargeID string, err error)

	// RedirectFailure redirects to the given returnTo address with the given error.
	RedirectFailure(ctx context.Context, w http.ResponseWriter, req *http.Request, returnTo, state string, err error)

	// RedirectSuccess redirects to the given returnTo address
	// providing a code which can be used by the client to obtain a
	// disharge token for the given id.
	RedirectSuccess(ctx context.Context, w http.ResponseWriter, req *http.Request, returnTo, state string, id *store.Identity)
}

// InitParams are passed to the identity provider to initialise it.
type InitParams struct {
	// Store contains the identity store being used in the identity
	// server.
	Store store.Store

	// KeyValueStore contains a store that the provider may use to
	// store additional data that is not related to identities.
	KeyValueStore simplekv.Store

	// Oven contains an oven that may be used in the identity
	// provider to mint new macaroons.
	Oven *bakery.Oven

	// Codec contains the codec used to encode/decode session cookies
	// in the login flow.
	Codec *secret.Codec

	// Location contains the root location of the candid server.
	Location string

	// URLPrefix contains the prefix of all requests to the Handle
	// method. The URL.Path parameter in the request passed to handle
	// will contain only the part after this prefix.
	URLPrefix string

	// DischargeTokenCreator is the DischargeTokenCreator that the identity
	// provider should use to create discharge tokens.
	DischargeTokenCreator DischargeTokenCreator

	// VisitCompleter is the LoginCompleter that the identity
	// provider should use to complete visit requests.
	VisitCompleter VisitCompleter

	// Template contains the templates loaded in the identity server.
	Template *template.Template

	// SkipLocationForCookiePaths instructs if the Cookie Paths are to
	// be set relative to the Location Path or not.
	SkipLocationForCookiePaths bool
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

	// IconURL returns the URL of an icon image that represents the
	// identity provider.
	IconURL() string

	// Interactive indicates whether login is provided by the end
	// user interacting directly with the identity provider (usually
	// through a web browser).
	Interactive() bool

	// Hidden indicates that the IDP should not be listed on the
	// interactive login page, unless it has specifically been
	// requested (via a domain).
	Hidden() bool

	// Init is used to perform any one time initialization tasks that
	// are needed for the identity provider. Init is called once by
	// the identity manager once it has determined the identity
	// providers final location, any initialization tasks that depend
	// on having access to the final URL, or the per identity
	// provider database should be performed here.
	Init(ctx context.Context, params InitParams) error

	// URL returns the URL to use to attempt a login with this
	// identity provider. If the identity provider is interactive
	// then the user will be redirected to the URL. Otherwise the URL
	// is returned in the response to a request for login methods.
	// The given state value should be round-tripped through the
	// login interaction and used to verify the login when it
	// completes.
	URL(state string) string

	// SetInteraction adds interaction information for this identity
	// provider to the given interaction required error.
	SetInteraction(ierr *httpbakery.Error, dischargeID string)

	// Handle handles any requests sent to the identity provider's
	// endpoints. The URL.Path in the request will contain only the
	// handler local path, that is the part after URLPrefix above.
	// The given request will have had ParseForm called.
	Handle(ctx context.Context, w http.ResponseWriter, req *http.Request)

	// GetGroups retrieves additional group information that is
	// stored in the identity provider for the given identity.
	// TODO define what happens when the identity doesn't exist.
	GetGroups(ctx context.Context, id *store.Identity) (groups []string, err error)
}
