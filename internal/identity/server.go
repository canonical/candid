// Copyright 2014 Canonical Ltd.

package identity

import (
	"fmt"
	"net/http"
	"time"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/mgo.v2"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity/params"
)

// NewAPIHandlerFunc is a function that returns a new API handler.
type NewAPIHandlerFunc func(*Pool, ServerParams) http.Handler

// New returns a handler that serves the given identity API versions using the
// db to store identity data. The key of the versions map is the version name.
func New(db *mgo.Database, sp ServerParams, versions map[string]NewAPIHandlerFunc) (*Server, error) {
	if len(versions) == 0 {
		return nil, errgo.Newf("identity server must serve at least one version of the API")
	}

	// Create the identities store.
	pool, err := NewPool(db, sp)
	if err != nil {
		return nil, errgo.Notef(err, "cannot make store")
	}
	// Create the HTTP server.
	srv := &Server{
		ServeMux: http.NewServeMux(),
		p:        pool,
	}
	srv.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		httprequest.WriteJSON(w, http.StatusNotFound, params.Error{
			Code:    params.ErrNotFound,
			Message: fmt.Sprintf("%q not found", req.URL.Path),
		})
	}))
	for vers, newAPI := range versions {
		handle(srv.ServeMux, "/"+vers, newAPI(pool, sp))
	}
	return srv, nil
}

// Server serves the identity endpoints.
type Server struct {
	*http.ServeMux
	p *Pool
}

// Close  closes any resources held by this Handler.
func (s *Server) Close() {
	logger.Debugf("Closing Server")
	s.p.Close()
}

func handle(mux *http.ServeMux, path string, handler http.Handler) {
	handler = http.StripPrefix(path, handler)
	mux.Handle(path+"/", handler)
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
}
