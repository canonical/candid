// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"
)

// GET /debug
func (h *Handler) serveDebug(http.ResponseWriter, *http.Request) error {
	return errNotImplemented
}

// GET /debug/status
func (h *Handler) serveDebugStatus(_ http.Header, req *http.Request) (interface{}, error) {
	// TODO frankban: implement the debug status handler.
	return nil, errNotImplemented
}
