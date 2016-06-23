// Copyright 2014 Canonical Ltd.

package identity

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/juju/loggo"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/mgo.v2"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

var logger = loggo.GetLogger("identity.internal.identity")

// NewAPIHandlerFunc is a function that returns set of httprequest
// handlers that uses the given Store pool, and server params.
type NewAPIHandlerFunc func(*store.Pool, ServerParams) ([]httprequest.Handler, error)

// New returns a handler that serves the given identity API versions using the
// db to store identity data. The key of the versions map is the version name.
func New(db *mgo.Database, sp ServerParams, versions map[string]NewAPIHandlerFunc) (*Server, error) {
	if len(versions) == 0 {
		return nil, errgo.Newf("identity server must serve at least one version of the API")
	}

	// Create the identities store.
	pool, err := store.NewPool(db, store.StoreParams{
		AuthUsername:   sp.AuthUsername,
		AuthPassword:   sp.AuthPassword,
		Key:            sp.Key,
		Location:       sp.Location,
		Launchpad:      sp.Launchpad,
		MaxMgoSessions: sp.MaxMgoSessions,
		RequestTimeout: sp.RequestTimeout,
		PrivateAddr:    sp.PrivateAddr,
	})
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
	srv.router.NotFound = http.HandlerFunc(notFound)
	srv.router.MethodNotAllowed = http.HandlerFunc(srv.methodNotAllowed)

	srv.router.Handle("OPTIONS", "/*path", srv.options)
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
	pool   *store.Pool
}

// ServeHTTP implements http.Handler.
func (srv *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if v := recover(); v != nil {
			logger.Errorf("PANIC!: %v\n%s", v, debug.Stack())
			httprequest.WriteJSON(w, http.StatusInternalServerError, params.Error{
				Code:    "panic",
				Message: fmt.Sprintf("%v", v),
			})
		}
	}()
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Bakery-Protocol-Version, Macaroons, X-Requested-With, Content-Type")
	w.Header().Set("Access-Control-Cache-Max-Age", "600")
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

	// PrivateAddr should hold a dialable address that will be used
	// for communication between identity servers. Note that this
	// should not contain a port.
	PrivateAddr string

	// IdentityProviders contains the set of identity providers that
	// should be initialised by the service.
	IdentityProviders []idp.IdentityProvider

	// DebugTeams contains the set of launchpad teams that may access
	// the restricted debug endpoints.
	DebugTeams []string
}

//notFound is the handler that is called when a handler cannot be found
//for the requested endpoint.
func notFound(w http.ResponseWriter, req *http.Request) {
	ErrorMapper.WriteError(w, errgo.WithCausef(nil, params.ErrNotFound, "not found: %s", req.URL.Path))
}

//methodNotAllowed is the handler that is called when a handler cannot
//be found for the requested endpoint with the request method, but
//there is a handler avaiable using a different method.
func (s *Server) methodNotAllowed(w http.ResponseWriter, req *http.Request) {
	// Check that the match method is not OPTIONS
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"} {
		if method == req.Method {
			continue
		}
		if h, _, _ := s.router.Lookup(method, req.URL.Path); h != nil {
			ErrorMapper.WriteError(w, errgo.WithCausef(nil, params.ErrMethodNotAllowed, "%s not allowed for %s", req.Method, req.URL.Path))
			return
		}
	}
	notFound(w, req)
}

// options handles every OPTIONS request and always succeeds.
func (s *Server) options(http.ResponseWriter, *http.Request, httprouter.Params) {
	return
}
