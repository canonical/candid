// Copyright 2014 Canonical Ltd.

package identity

import (
	"net/http"
	"time"

	"github.com/juju/httprequest"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/mgo.v2"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity/params"
)

// NewAPIHandlerFunc is a function that returns set of httprequest
// handlers that uses the given Store pool and server params.
type NewAPIHandlerFunc func(*Pool, ServerParams) ([]httprequest.Handler, error)

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
		router: httprouter.New(),
		pool:   pool,
	}
	// Disable the automatic rerouting in order to maintain
	// compatibility. It might be worthwhile relaxing this in the
	// future.
	srv.router.RedirectTrailingSlash = false
	srv.router.RedirectFixedPath = false
	srv.router.NotFound = notFound
	srv.router.MethodNotAllowed = methodNotAllowed
	for name, newAPI := range versions {
		handlers, err := newAPI(pool, sp)
		if err != nil {
			return nil, errgo.Notef(err, "cannot create API %s", name)
		}
		for _, h := range handlers {
			srv.router.Handle(h.Method, h.Path, h.Handle)
		}
	}
	return srv, nil
}

// Server serves the identity endpoints.
type Server struct {
	router *httprouter.Router
	pool   *Pool
}

// ServeHTTP implements http.Handler.
func (srv *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	srv.router.ServeHTTP(w, req)
}

// Close  closes any resources held by this Handler.
func (s *Server) Close() {
	logger.Debugf("Closing Server")
	s.pool.Close()
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

//notFound is the handler that is called when a handler cannot be found
//for the requested endpoint.
func notFound(w http.ResponseWriter, req *http.Request) {
	ErrorMapper.WriteError(w, errgo.WithCausef(nil, params.ErrNotFound, "not found: %s", req.URL.Path))
}

//methodNotAllowed is the handler that is called when a handler cannot
//be found for the requested endpoint with the request method, but
//there is a handler avaiable using a different method.
func methodNotAllowed(w http.ResponseWriter, req *http.Request) {
	ErrorMapper.WriteError(w, errgo.WithCausef(nil, params.ErrMethodNotAllowed, "%s not allowed for %s", req.Method, req.URL.Path))
}
