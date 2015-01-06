// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"

	"github.com/juju/httpprof"
	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v0/bakery"
	"gopkg.in/macaroon-bakery.v0/httpbakery"

	"github.com/CanonicalLtd/blues-identity/internal/router"
	"github.com/CanonicalLtd/blues-identity/internal/server"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

var logger = loggo.GetLogger("identity.internal.v1")

// NewAPIHandler returns a new instance of the v1 API handler.
func NewAPIHandler(s *store.Store, auth *server.Authorizer, svc *bakery.Service) http.Handler {
	h := &Handler{
		store: s,
		svc:   svc,
	}
	mux := http.NewServeMux()
	httpbakery.AddDischargeHandler(mux, "/", svc, h.checkThirdPartyCaveat)
	h.Router = router.New(map[string]http.Handler{
		"debug":      router.HandleErrors(h.serveDebug),
		"debug/info": router.HandleJSON(h.serveDebugInfo),
		"debug/pprof/": router.AuthorizingHandler{
			CheckAuthorized: auth.HasAdminCredentials,
			Handler:         pprof.IndexAtRoot("/"),
		},
		"debug/pprof/cmdline": router.AuthorizingHandler{
			CheckAuthorized: auth.HasAdminCredentials,
			Handler:         http.HandlerFunc(pprof.Cmdline),
		},
		"debug/pprof/profile": router.AuthorizingHandler{
			CheckAuthorized: auth.HasAdminCredentials,
			Handler:         http.HandlerFunc(pprof.Profile),
		},
		"debug/pprof/symbol": router.AuthorizingHandler{
			CheckAuthorized: auth.HasAdminCredentials,
			Handler:         http.HandlerFunc(pprof.Symbol),
		},
		"debug/status": router.HandleJSON(h.serveDebugStatus),
		"discharge/":   mux,
		"idps/": router.AuthorizingHandler{
			CheckAuthorized: router.Any(
				router.HasMethod("GET"),
				auth.HasAdminCredentials,
			),
			Handler: router.HandleJSON(h.serveIdentityProviders),
		},
		"u": router.AuthorizingHandler{
			CheckAuthorized: router.HasMethod("POST"),
			Handler:         router.HandleJSON(h.serveCreateUser),
		},
		"u/": router.HandleJSON(h.serveUser),
	})
	return h
}

type Handler struct {
	*router.Router
	store *store.Store
	svc   *bakery.Service
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.Router.ServeHTTP(w, req)
}

var errNotImplemented = errgo.Newf("method not implemented")
