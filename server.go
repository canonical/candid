// Copyright 2014 Canonical Ltd.

package identity

import (
	"net/http"
	"sort"
	"time"

	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/mgo.v2"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/v1"
)

// Versions of the API that can be served.
const (
	V1 = "v1"
)

var versions = map[string]identity.NewAPIHandlerFunc{
	V1: v1.NewAPIHandler,
}

// Versions returns all known API version strings in alphabetical order.
func Versions() []string {
	vs := make([]string, 0, len(versions))
	for v := range versions {
		vs = append(vs, v)
	}
	sort.Strings(vs)
	return vs
}

// ServerParams contains configuration parameters for a server.
type ServerParams struct {
	// AuthUsername holds the username for admin login.
	AuthUsername string

	// AuthPassword holds the password for admin login.
	AuthPassword string

	// Key holds the keypair to use with the bakery service.
	Key *bakery.KeyPair

	// Location holds a URL representing the externally accessible
	// base URL of the service, without a trailing slash.
	Location string

	// Launchpad holds the address of the launchpad server to use to
	// get group information.
	Launchpad lpad.APIBase

	// MaxMgoSession holds the maximum number of concurrent mgo
	// sessions.
	MaxMgoSessions int

	// RequestTimeout holds the time to wait for a request to be able
	// to start.
	RequestTimeout time.Duration

	// PrivateAddr should hold a dialable address that will be used
	// for communication between identity servers. Note that this
	// should not contain a port.
	PrivateAddr string

	// IdentityProviders contains the set of identity providers that
	// should be initialised by the service.
	IdentityProviders []idp.IdentityProvider
}

// NewServer returns a new handler that handles identity service requests and
// stores its data in the given database. The handler will serve the specified
// versions of the API.
func NewServer(db *mgo.Database, params ServerParams, serveVersions ...string) (HandlerCloser, error) {
	newAPIs := make(map[string]identity.NewAPIHandlerFunc)
	for _, vers := range serveVersions {
		newAPI := versions[vers]
		if newAPI == nil {
			return nil, errgo.Newf("unknown version %q", vers)
		}
		newAPIs[vers] = newAPI
	}
	return identity.New(db, identity.ServerParams(params), newAPIs)
}

type HandlerCloser interface {
	http.Handler
	Close()
}
