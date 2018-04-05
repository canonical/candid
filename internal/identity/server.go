// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package identity

import (
	"fmt"
	"html/template"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/juju/loggo"
	"github.com/juju/utils/debugstatus"
	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/internal/auth"
	"github.com/CanonicalLtd/candid/internal/monitoring"
	"github.com/CanonicalLtd/candid/meeting"
	"github.com/CanonicalLtd/candid/store"
)

var logger = loggo.GetLogger("candid.internal.identity")

// NewAPIHandlerFunc is a function that returns set of httprequest
// handlers that uses the given Store pool, and server params.
type NewAPIHandlerFunc func(HandlerParams) ([]httprequest.Handler, error)

// New returns a handler that serves the given identity API versions using the
// db to store identity data. The key of the versions map is the version name.
func New(sp ServerParams, versions map[string]NewAPIHandlerFunc) (*Server, error) {
	if len(versions) == 0 {
		return nil, errgo.Newf("identity server must serve at least one version of the API")
	}

	// Create the bakery parts.
	if sp.Key == nil {
		var err error
		sp.Key, err = bakery.GenerateKey()
		if err != nil {
			return nil, errgo.Notef(err, "cannot generate key")
		}
	}
	locator := bakery.NewThirdPartyStore()
	locator.AddInfo(sp.Location, bakery.ThirdPartyInfo{
		PublicKey: sp.Key.Public,
		Version:   bakery.LatestVersion,
	})
	var rksf func([]bakery.Op) bakery.RootKeyStore
	if sp.RootKeyStore != nil {
		rksf = func([]bakery.Op) bakery.RootKeyStore {
			return sp.RootKeyStore
		}
	}
	oven := bakery.NewOven(bakery.OvenParams{
		Namespace:          auth.Namespace,
		RootKeyStoreForOps: rksf,
		Key:                sp.Key,
		Locator:            locator,
		Location:           "identity",
	})
	auth := auth.New(auth.Params{
		AdminUsername:     sp.AuthUsername,
		AdminPassword:     sp.AuthPassword,
		Location:          sp.Location,
		MacaroonVerifier:  oven,
		Store:             sp.Store,
		IdentityProviders: sp.IdentityProviders,
	})
	if err := auth.SetAdminPublicKey(context.Background(), sp.AdminAgentPublicKey); err != nil {
		return nil, errgo.Mask(err)
	}

	place, err := meeting.NewPlace(meeting.Params{
		Store:       sp.MeetingStore,
		Metrics:     monitoring.NewMeetingMetrics(),
		ListenAddr:  sp.PrivateAddr,
		WaitTimeout: sp.WaitTimeout,
	})
	if err != nil {
		return nil, errgo.Notef(err, "cannot create meeting place")
	}

	// Create the HTTP server.
	srv := &Server{
		router:       httprouter.New(),
		meetingPlace: place,
	}
	// Disable the automatic rerouting in order to maintain
	// compatibility. It might be worthwhile relaxing this in the
	// future.
	srv.router.RedirectTrailingSlash = false
	srv.router.RedirectFixedPath = false
	srv.router.NotFound = http.HandlerFunc(notFound)
	srv.router.MethodNotAllowed = http.HandlerFunc(srv.methodNotAllowed)

	srv.router.Handle("OPTIONS", "/*path", srv.options)
	srv.router.Handler("GET", "/metrics", prometheus.Handler())
	srv.router.Handler("GET", "/static/*path", http.StripPrefix("/static", http.FileServer(sp.StaticFileSystem)))
	for name, newAPI := range versions {
		handlers, err := newAPI(HandlerParams{
			ServerParams: sp,
			Oven:         oven,
			Authorizer:   auth,
			MeetingPlace: place,
		})
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
	router       *httprouter.Router
	meetingPlace *meeting.Place
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
	s.meetingPlace.Close()
}

// ServerParams contains configuration parameters for a server.
type ServerParams struct {
	// MeetingStore holds the storage that will be used to store
	// rendezvous information.
	MeetingStore meeting.Store

	// ProviderDataStore holds the storeage that can be used by
	// identity providers to store data that is not associated with
	// an individual identity.
	ProviderDataStore store.ProviderDataStore

	// RootKeyStore holds the root key store that will be used to
	// store macaroon root keys within the identity server.
	RootKeyStore bakery.RootKeyStore

	// Store holds the identities store for the identity server.
	Store store.Store

	// AuthUsername holds the username for admin login.
	AuthUsername string

	// AuthPassword holds the password for admin login.
	AuthPassword string

	// Key holds the keypair to use with the bakery service.
	Key *bakery.KeyPair

	// Location holds a URL representing the externally accessible
	// base URL of the service, without a trailing slash.
	Location string

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

	// AdminAgentPublicKey contains the public key of the admin agent.
	AdminAgentPublicKey *bakery.PublicKey

	// StaticFileSystem contains an http.FileSystem that can be used
	// to serve static files.
	StaticFileSystem http.FileSystem

	// Template contains a set of templates that are used to generate
	// html output.
	Template *template.Template

	// DebugStatusCheckerFuncs contains functions that will be
	// executed as part of a /debug/status check.
	DebugStatusCheckerFuncs []debugstatus.CheckerFunc

	// WaitTimeout holds the time after which an interactive discharge wait
	// request will timeout.
	WaitTimeout time.Duration
}

type HandlerParams struct {
	ServerParams

	// Oven contains a bakery.Oven that should be used by handlers to
	// mint new macaroons.
	Oven *bakery.Oven

	// Authorizer contains an auth.Authroizer that should be used by
	// handlers to authorize requests.
	Authorizer *auth.Authorizer

	// MeetingPlace contains the meeting place that should be used by
	// handlers to complete rendezvous.
	MeetingPlace *meeting.Place
}

//notFound is the handler that is called when a handler cannot be found
//for the requested endpoint.
func notFound(w http.ResponseWriter, req *http.Request) {
	WriteError(context.TODO(), w, errgo.WithCausef(nil, params.ErrNotFound, "not found: %s", req.URL.Path))
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
			WriteError(context.TODO(), w, errgo.WithCausef(nil, params.ErrMethodNotAllowed, "%s not allowed for %s", req.Method, req.URL.Path))
			return
		}
	}
	notFound(w, req)
}

// options handles every OPTIONS request and always succeeds.
func (s *Server) options(http.ResponseWriter, *http.Request, httprouter.Params) {}
