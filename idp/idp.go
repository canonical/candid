// Copyright 2015 Canonical Ltd.

// Package idp defines the API provided by all identity providers.
package idp

import (
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/mgo.v2"
)

// URLContext is the interface expected by the IdentityProvider.URL
// method. It allows an identity provider to define a URL destined for
// its Handle method.
type URLContext interface {
	// URL returns a URL addressed to path within the identity provider.
	URL(path string) string
}

// Context provides information about the identity-manager context
// to an identity provider. The context is specific to a given client
// HTTP request to the identity provider.
type Context interface {
	URLContext

	// RequestURL gets the original URL used to initiate the request
	RequestURL() string

	// Params gets the params for the current request.
	Params() httprequest.Params

	// LoginSuccess completes a login request successfully. The user
	// with the given username will have their last login time
	// updated in the database. A new identity macaroon will be minted
	// for the user with the given expiry time.
	//
	// LoginSuccess will return true if the login was completed
	// successfully so that the IDP may return an appropriate success
	// response to the interracting client. If there was an error
	// completing the login attempt, an error will have automatically
	// been returned to the client and false will be returned.
	LoginSuccess(user params.Username, expiry time.Time) bool

	// LoginFailure fails a login request.
	LoginFailure(error)

	// Bakery returns a *bakery.Bakery that the identity provider
	// should use to mint new macaroons.
	Bakery() *bakery.Bakery

	// UpdateUser creates or updates the record for the given user in
	// the database.
	UpdateUser(*params.User) error

	// FindUserByName finds the user with the given username.
	FindUserByName(params.Username) (*params.User, error)

	// FindUserByExternalId finds the user with the given external Id.
	FindUserByExternalId(string) (*params.User, error)

	// Database returns a mgo.Database that the identity provider may use to
	// store any necessary state data.
	Database() *mgo.Database
}

// IdentityProvider is the interface that is satisfied by all identity providers.
type IdentityProvider interface {
	// Name is the short name for the identity provider, this will
	// appear in urls.
	Name() string

	// Description is a name for the identity provider used to show
	// end users.
	Description() string

	// Interactive indicates whether login is provided by the end
	// user interacting directly with the identity provider (usually
	// through a web browser).
	Interactive() bool

	// URL returns the URL to use to attempt a login with this
	// identity provider. If the identity provider is interactive
	// then the user will be automatically redirected to the URL.
	// Otherwise the URL is returned in the response to a
	// request for login methods.
	URL(c URLContext, waitid string) (string, error)

	// Handle handles any requests sent to the identity provider's
	// endpoints. All URLs returned by URLContext.URL will be
	// directed to Handle.
	Handle(c Context)
}
