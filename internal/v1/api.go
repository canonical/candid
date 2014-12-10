// Copyright 2014 Canonical Ltd.

package v1

import (
	"encoding/json"
	"net/http"

	"github.com/juju/loggo"

	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/params"
)

var logger = loggo.GetLogger("identity.internal.v1")

// NewAPIHandler returns a new instance of the v1 API handler.
func NewAPIHandler(s *store.Store) http.Handler {
	return &Handler{
		store: s,
	}
}

type Handler struct {
	store *store.Store
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// TODO: implement the API v1.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	// TODO frankban: use github.com/juju/utils/jsonhttp in real code.
	json.NewEncoder(w).Encode(params.Error{
		Message: "method not implemented",
	})
}
