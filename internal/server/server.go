// Copyright 2014 Canonical Ltd.

package server

import (
	"net/http"

	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"
)

// NewAPIHandlerFunc is a function that returns a new API handler.
// TODO (frankban): make this function receive the db object
//                  (or more likely a store object).
type NewAPIHandlerFunc func() http.Handler

// New returns a handler that serves the given identity API versions using the
// db to store identity data. The key of the versions map is the version name.
func New(db *mgo.Database, versions map[string]NewAPIHandlerFunc) (http.Handler, error) {
	if len(versions) == 0 {
		return nil, errgo.Newf("identity server must serve at least one version of the API")
	}

	mux := http.NewServeMux()
	for vers, newAPI := range versions {
		handle(mux, "/"+vers, newAPI())
	}
	// TODO (frankban): implement a router and use
	// github.com/juju/utils/jsonhttp.
	handle(mux, "", http.HandlerFunc(notFoundHandler))
	return mux, nil
}

func handle(mux *http.ServeMux, path string, handler http.Handler) {
	handler = http.StripPrefix(path, handler)
	mux.Handle(path+"/", handler)
}

func notFoundHandler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}
