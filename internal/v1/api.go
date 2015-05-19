// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"

	"github.com/juju/httpprof"
	"github.com/juju/loggo"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/httpbakery"

	"github.com/CanonicalLtd/blues-identity/internal/server"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/params"
)

var logger = loggo.GetLogger("identity.internal.v1")

// Handler handles the /v1 api requests. Handler implements http.Handler
type Handler struct {
	location string
	r        *httprouter.Router
	store    *store.Store
	svc      *bakery.Service
	place    *place
	provider *ussoProvider
	auth     *server.Authorizer
}

// NewAPIHandler returns a new Handler as an http Handler.
// It is defined for the convenience of callers that require a
// server.NewAPIHandlerFunc.
func NewAPIHandler(s *store.Store, auth *server.Authorizer, svc *bakery.Service) http.Handler {
	return New(s, auth, svc)
}

// New returns a new instance of the v1 API handler.
func New(s *store.Store, auth *server.Authorizer, svc *bakery.Service) *Handler {
	h := &Handler{
		location: svc.Location(),
		r:        httprouter.New(),
		store:    s,
		svc:      svc,
		place:    &place{s.Place},
		auth:     auth,
	}
	h.provider = newUSSOProvider(h, h.location+"/v1/idp/usso")
	h.r.NotFound = notFound
	h.r.MethodNotAllowed = methodNotAllowed
	// Redirection does not work because the router does not know
	// about the /v1 prefix. Disable the automatic redirection features.
	h.r.RedirectTrailingSlash = false
	h.r.RedirectFixedPath = false
	h.r.POST("/agent", handle(h.agentLogin))
	mux := http.NewServeMux()
	const dischargePath = "/discharger"
	httpbakery.AddDischargeHandler(mux, dischargePath, svc, h.checkThirdPartyCaveat)
	h.r.GET("/debug", handleErrors(h.serveDebug))
	h.r.GET("/debug/info", handleJSON(h.serveDebugInfo))
	h.r.GET("/debug/pprof", h.adminRequiredHandler(pprof.IndexAtRoot("/debug/pprof")))
	h.r.GET("/debug/pprof/cmdline", h.adminRequiredHandler(http.HandlerFunc(pprof.Cmdline)))
	h.r.GET("/debug/pprof/profile", h.adminRequiredHandler(http.HandlerFunc(pprof.Profile)))
	h.r.GET("/debug/pprof/symbol", h.adminRequiredHandler(http.HandlerFunc(pprof.Symbol)))
	h.r.GET("/debug/status", handleJSON(h.serveDebugStatus))
	h.r.Handler("GET", dischargePath+"/*path", mux)
	h.r.Handler("POST", dischargePath+"/*path", mux)
	h.r.Handler("GET", "/idp/usso/*path", http.StripPrefix("/idp/usso", h.provider.handler()))
	h.r.GET("/idps", handleJSON(h.serveIdentityProviders))
	h.r.GET("/idps/:idp", handle(h.serveIdentityProvider))
	h.r.PUT("/idps/:idp", h.adminRequired(handle(h.servePutIdentityProvider)))
	h.r.GET("/login", handleErrors(h.login))
	h.r.GET("/u", h.adminRequired(handle(h.serveQueryUsers)))
	h.r.GET("/u/:username", h.adminRequired(handle(h.serveUser)))
	h.r.PUT("/u/:username", h.adminRequired(handle(h.servePutUser)))
	h.r.GET("/u/:username/extra-info", h.adminRequired(handle(h.serveUserExtraInfo)))
	h.r.PUT("/u/:username/extra-info", h.adminRequired(handle(h.serveUserPutExtraInfo)))
	h.r.GET("/u/:username/extra-info/:item", h.adminRequired(handle(h.serveUserExtraInfoItem)))
	h.r.PUT("/u/:username/extra-info/:item", h.adminRequired(handle(h.serveUserPutExtraInfoItem)))
	h.r.GET("/u/:username/idpgroups", h.adminRequired(handle(h.serveUserGroups)))
	h.r.GET("/u/:username/macaroon", h.adminRequired(handle(h.serveUserToken)))
	h.r.GET("/wait", handle(h.serveWait))
	h.r.POST("/verify", handle(h.serveVerifyToken))
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.r.ServeHTTP(w, req)
}

var errNotImplemented = errgo.Newf("method not implemented")

// requestURL calculates the originally requested URL for the
// provided http.Request.
func (h *Handler) requestURL(r *http.Request) string {
	return h.location + r.RequestURI
}

func (h *Handler) adminRequired(f httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
		if err := h.auth.CheckAdminCredentials(req); err != nil {
			writeError(w, err)
			return
		}
		f(w, req, p)
	}
}

func (h *Handler) adminRequiredHandler(handler http.Handler) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		if err := h.auth.CheckAdminCredentials(req); err != nil {
			writeError(w, err)
			return
		}
		handler.ServeHTTP(w, req)
	}
}

//notFound is the handler that is called when a handler cannot be found
//for the requested endpoint.
func notFound(w http.ResponseWriter, req *http.Request) {
	writeError(w, errgo.WithCausef(nil, params.ErrNotFound, "not found: %s", req.URL.Path))
}

//methodNotAllowed is the handler that is called when a handler cannot
//be found for the requested endpoint with the request method, but
//there is a handler avaiable using a different method.
func methodNotAllowed(w http.ResponseWriter, req *http.Request) {
	writeError(w, errgo.WithCausef(nil, params.ErrMethodNotAllowed, "%s not allowed for %s", req.Method, req.URL.Path))
}
