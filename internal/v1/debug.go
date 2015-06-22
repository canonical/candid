// Copyright 2014 Canonical Ltd.

package v1

import (
	"github.com/juju/httpprof"
	"github.com/juju/httprequest"
	"github.com/juju/utils/debugstatus"

	"github.com/CanonicalLtd/blues-identity/version"
)

type debugRequest struct {
	httprequest.Route `httprequest:"GET /debug"`
}

// GET /debug
func (h *handler) ServeDebug(*debugRequest) error {
	return errNotImplemented
}

type debugStatusRequest struct {
	httprequest.Route `httprequest:"GET /debug/status"`
}

// GET /debug/status
func (h *handler) ServeDebugStatus(*debugStatusRequest) (map[string]debugstatus.CheckResult, error) {
	return debugstatus.Check(
		debugstatus.ServerStartTime,
		debugstatus.Connection(h.store.DB.Session),
		debugstatus.MongoCollections(h.store.DB),
	), nil
}

type debugInfoRequest struct {
	httprequest.Route `httprequest:"GET /debug/info"`
}

// GET /debug/info .
func (h *handler) ServeDebugInfo(*debugInfoRequest) (version.Version, error) {
	return version.VersionInfo, nil
}

type debugPprofRequest struct {
	httprequest.Route `httprequest:"GET /debug/pprof/"`
}

// GET /debug/pprof/
func (h *handler) ServeDebugPprof(p httprequest.Params, _ *debugPprofRequest) {
	if err := h.checkAdmin(p.Request); err != nil {
		writeError(p.Response, err)
		return
	}
	pprof.IndexAtRoot("/debug/pprof/").ServeHTTP(p.Response, p.Request)
}

type debugPprofHandlerRequest struct {
	httprequest.Route `httprequest:"GET /debug/pprof/:name"`
	Name              string `httprequest:"name,path"`
}

// GET /debug/pprof/:handler
func (h *handler) ServeDebugPprofHandler(p httprequest.Params, r *debugPprofHandlerRequest) {
	if err := h.checkAdmin(p.Request); err != nil {
		writeError(p.Response, err)
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
