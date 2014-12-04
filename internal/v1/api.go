// Copyright 2014 Canonical Ltd.

package v1

import (
	"encoding/json"
	"net/http"

	"github.com/juju/loggo"

	"github.com/CanonicalLtd/blues-identity/params"
)

var logger = loggo.GetLogger("identity.internal.v1")

// NewAPIHandler returns a new instance of the v1 API handler.
func NewAPIHandler() http.Handler {
	// TODO: implement the API v1.
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// TODO (frankban): use github.com/juju/utils/jsonhttp in real code.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(params.Error{
			Message: "method not implemented",
		})
	})
}
