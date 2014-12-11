// Copyright 2014 Canonical Ltd.

package router

import (
	"net/http"

	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/params"
)

// NewServeMux creates an HTTP mux, similar to http.ServeMux but returning
// JSON errors when pages are not found.
func NewServeMux() *ServeMux {
	return &ServeMux{http.NewServeMux()}
}

type ServeMux struct {
	*http.ServeMux
}

func (mux *ServeMux) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h, pattern := mux.Handler(req)
	if pattern == "" {
		WriteError(w, errgo.WithCausef(nil, params.ErrNotFound, "no handler for %q", req.URL.Path))
		return
	}
	h.ServeHTTP(w, req)
}
