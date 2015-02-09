// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"

	"github.com/juju/httprequest"
	"github.com/juju/utils/debugstatus"

	"github.com/CanonicalLtd/blues-identity/version"
)

// GET /debug
func (h *Handler) serveDebug(http.ResponseWriter, httprequest.Params) error {
	return errNotImplemented
}

// GET /debug/status
func (h *Handler) serveDebugStatus(http.Header, httprequest.Params) (interface{}, error) {
	return debugstatus.Check(
		debugstatus.ServerStartTime,
		debugstatus.Connection(h.store.DB.Session),
		debugstatus.MongoCollections(h.store.DB),
	), nil
}

// GET /debug/info .
func (h *Handler) serveDebugInfo(http.Header, httprequest.Params) (interface{}, error) {
	return version.VersionInfo, nil
}
