// Copyright 2014 Canonical Ltd.

package server

import (
	"fmt"
	"net/http"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v0/bakery"
	"gopkg.in/macaroon-bakery.v0/bakery/mgostorage"
	"gopkg.in/mgo.v2"

	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/params"
)

// NewAPIHandlerFunc is a function that returns a new API handler.
type NewAPIHandlerFunc func(*store.Store, *Authorizer, *bakery.Service) http.Handler

// New returns a handler that serves the given identity API versions using the
// db to store identity data. The key of the versions map is the version name.
func New(db *mgo.Database, p ServerParams, versions map[string]NewAPIHandlerFunc) (http.Handler, error) {
	if len(versions) == 0 {
		return nil, errgo.Newf("identity server must serve at least one version of the API")
	}

	// Create the identities store.
	store, err := store.New(db)
	if err != nil {
		return nil, errgo.Notef(err, "cannot make store")
	}

	// Create the Authorization.
	auth := NewAuthorizer(p)

	// Create Macaroon storage.
	ms, err := mgostorage.New(store.DB.Macaroons())
	if err != nil {
		return nil, errgo.Notef(err, "cannot create macaroon store")
	}

	// Create the bakery Service.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Location: p.Location,
		Store:    ms,
		Key:      p.Key,
	})
	if err != nil {
		return nil, errgo.Notef(err, "cannot create bakery service")
	}

	// Create the HTTP server.
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		httprequest.WriteJSON(w, http.StatusNotFound, params.Error{
			Code:    params.ErrNotFound,
			Message: fmt.Sprintf("%q not found", req.URL.Path),
		})
	}))
	for vers, newAPI := range versions {
		handle(mux, "/"+vers, newAPI(store, auth, svc))
	}
	return mux, nil
}

func handle(mux *http.ServeMux, path string, handler http.Handler) {
	handler = http.StripPrefix(path, handler)
	mux.Handle(path+"/", handler)
}

// ServerParams contains configuration parameters for a server.
type ServerParams struct {
	AuthUsername string
	AuthPassword string
	Key          *bakery.KeyPair
	// Location holds a URL representing the externally accessible
	// base URL of the service, without a trailing slash.
	Location string
}
