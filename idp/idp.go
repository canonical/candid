// Copyright 2015 Canonical Ltd.

// Package idp defines the API provided by all identity providers.
package idp

import (
	"html/template"
	"net/http"
	"time"

	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/mgo.v2"
)

// Context provides information about the identity-manager context
// into which the identity provider is placed.
type Context interface {
	context.Context

	// URL returns a URL addressed to path within the identity provider.
	URL(path string) string

	// Database returns a mgo.Database that the identity provider may use to
	// store any necessary state data.
	Database() *mgo.Database
}

// RequestContext provides information about the identity-manager context
// of a particular identity provider request.
type RequestContext interface {
	Context

	// RequestURL gets the original URL used to initiate the request
	RequestURL() string

	// Path returns the part of the path following the part that
	// directed the request to this IDP handler.
	Path() string

	// Bakery returns a *bakery.Bakery that the identity provider
	// can use to mint new macaroons.
	Bakery() *bakery.Bakery

	// Template returns the template with the given name from the set
	// of templates configured in the server, or nil if there is no
	// such template.
	Template(name string) *template.Template

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
	LoginSuccess(waitid string, user params.Username, expiry time.Time) bool

	// LoginFailure fails a login request.
	LoginFailure(waitid string, err error)

	// UpdateUser creates or updates the record for the given user in
	// the database.
	UpdateUser(*params.User) error

	// FindUserByName finds the user with the given username.
	FindUserByName(params.Username) (*params.User, error)

	// FindUserByExternalId finds the user with the given external Id.
	FindUserByExternalId(string) (*params.User, error)
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
	Init(ctx Context) error

	// URL returns the URL to use to attempt a login with this
	// identity provider. If the identity provider is interactive
	// then the user will be automatically redirected to the URL.
	// Otherwise the URL is returned in the response to a
	// request for login methods.
	URL(ctx Context, waitid string) string

	// Handle handles any requests sent to the identity provider's
	// endpoints. All URLs returned by Context.URL will be directed
	// to Handle. The given request will have had ParseForm called.
	Handle(ctx RequestContext, w http.ResponseWriter, req *http.Request)
}
