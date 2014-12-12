// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"

	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/internal/router"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

var logger = loggo.GetLogger("identity.internal.v1")

// NewAPIHandler returns a new instance of the v1 API handler.
func NewAPIHandler(s *store.Store) http.Handler {
	h := &Handler{
		store: s,
	}
	h.Router = router.New(map[string]http.Handler{
		"debug":        router.HandleErrors(h.serveDebug),
		"debug/info":   router.HandleJSON(h.serveDebugInfo),
		"debug/status": router.HandleJSON(h.serveDebugStatus),
	})
	return h
}

type Handler struct {
	*router.Router
	store *store.Store
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.Router.ServeHTTP(w, req)
}

var errNotImplemented = errgo.Newf("method not implemented")
