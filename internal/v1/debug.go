// Copyright 2014 Canonical Ltd.

package v1

import (
	"github.com/juju/httpprof"
	"github.com/juju/httprequest"
	"github.com/juju/utils/debugstatus"

	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/version"
)

// debugStatusRequest documents the /v1/debug/status endpoint. As
// it contains no request information there is no need to ever create
// one.
type debugStatusRequest struct {
	httprequest.Route `httprequest:"GET /v1/debug/status"`
}

// GET /debug/status
func (h *debugHandler) DebugStatus(*debugStatusRequest) (map[string]debugstatus.CheckResult, error) {
	return debugstatus.Check(
		debugstatus.ServerStartTime,
		debugstatus.Connection(h.store.DB.Session),
		debugstatus.MongoCollections(h.store.DB),
	), nil
}

// debugInfoRequest documents the /debug/info endpoint. As
// it contains no request information there is no need to ever create
// one.
type debugInfoRequest struct {
	httprequest.Route `httprequest:"GET /debug/info"`
}

// GET /debug/info .
func (h *debugHandler) ServeDebugInfo(*debugInfoRequest) (version.Version, error) {
	return version.VersionInfo, nil
}

// debugPprofRequest documents the /debug/pprof endpoint. As
// it contains no request information there is no need to ever create
// one.
type debugPprofRequest struct {
	httprequest.Route `httprequest:"GET /debug/pprof/"`
}

// GET /debug/pprof/
func (h *debugHandler) ServeDebugPprof(p httprequest.Params, _ *debugPprofRequest) {
	if err := h.checkAdmin(); err != nil {
		identity.WriteError(p.Response, err)
		return
	}
	pprof.IndexAtRoot(h.serviceURL("/debug/pprof/")).ServeHTTP(p.Response, p.Request)
}

// DebugPprofHandlerRequest is a request to the specified /debug/pprof
// handler.
type debugPprofHandlerRequest struct {
	httprequest.Route `httprequest:"GET /debug/pprof/:name"`
	Name              string `httprequest:"name,path"`
}

// GET /debug/pprof/:handler
func (h *debugHandler) ServeDebugPprofHandler(p httprequest.Params, r *debugPprofHandlerRequest) {
	if err := h.checkAdmin(); err != nil {
		identity.WriteError(p.Response, err)
		return
	}
	switch r.Name {
	case "cmdline":
		pprof.Cmdline(p.Response, p.Request)
	case "profile":
		pprof.Profile(p.Response, p.Request)
	case "symbol":
		pprof.Symbol(p.Response, p.Request)
	default:
		pprof.Handler(r.Name).ServeHTTP(p.Response, p.Request)
	}
}
