// Copyright 2014 Canonical Ltd.

package server

import (
	"net/http"

	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"

	"github.com/CanonicalLtd/blues-identity/internal/router"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

// NewAPIHandlerFunc is a function that returns a new API handler.
type NewAPIHandlerFunc func(*store.Store, *Authorizer) http.Handler

// New returns a handler that serves the given identity API versions using the
// db to store identity data. The key of the versions map is the version name.
func New(db *mgo.Database, params ServerParams, versions map[string]NewAPIHandlerFunc) (http.Handler, error) {
	if len(versions) == 0 {
		return nil, errgo.Newf("identity server must serve at least one version of the API")
	}

	// Create the identities store.
	store, err := store.New(db)
	if err != nil {
		return nil, errgo.Notef(err, "cannot make store")
	}

	// Create the Authorization.
	auth := NewAuthorizer(params)

	// Create the HTTP server.
	mux := router.NewServeMux()
	for vers, newAPI := range versions {
		handle(mux, "/"+vers, newAPI(store, auth))
	}
	return mux, nil
}

func handle(mux *router.ServeMux, path string, handler http.Handler) {
	handler = http.StripPrefix(path, handler)
	mux.Handle(path+"/", handler)
}

// ServerParams contains configuration parameters for a server.
type ServerParams struct {
	AuthUsername string
	AuthPassword string
}
