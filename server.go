// Copyright 2014 Canonical Ltd.

package identity

import (
	"net/http"
	"sort"

	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v0/bakery"
	"gopkg.in/mgo.v2"

	"github.com/CanonicalLtd/blues-identity/internal/server"
	"github.com/CanonicalLtd/blues-identity/internal/v1"
)

// Versions of the API that can be served.
const (
	V1 = "v1"
)

var versions = map[string]server.NewAPIHandlerFunc{
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

// ServerParams holds configuration for a new API server.
type ServerParams struct {
	AuthUsername string
	AuthPassword string
	Key          *bakery.KeyPair
	// Location holds a URL representing the externally accessible
	// base URL of the service, without a trailing slash.
	Location string
}

// NewServer returns a new handler that handles identity service requests and
// stores its data in the given database. The handler will serve the specified
// versions of the API.
func NewServer(db *mgo.Database, params ServerParams, serveVersions ...string) (http.Handler, error) {
	newAPIs := make(map[string]server.NewAPIHandlerFunc)
	for _, vers := range serveVersions {
		newAPI := versions[vers]
		if newAPI == nil {
			return nil, errgo.Newf("unknown version %q", vers)
		}
		newAPIs[vers] = newAPI
	}
	return server.New(db, server.ServerParams(params), newAPIs)
}
