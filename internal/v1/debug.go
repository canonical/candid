// Copyright 2014 Canonical Ltd.

package v1

import (
	"fmt"
	"strconv"

	"github.com/juju/httpprof"
	"github.com/juju/httprequest"
	"github.com/juju/utils/debugstatus"
	"gopkg.in/mgo.v2"

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
	checks := []debugstatus.CheckerFunc{
		debugstatus.ServerStartTime,
		debugstatus.Connection(h.store.DB.Session),
		debugstatus.MongoCollections(h.store.DB),
		h.meetingStatus(),
		h.storePoolStatus()}
	if NoncesStatus != nil {
		checks = append(checks, NoncesStatus)
	}
	return debugstatus.Check(checks...), nil
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

func (h *debugHandler) meetingStatus() debugstatus.CheckerFunc {
	return func() (key string, result debugstatus.CheckResult) {
		result.Name = "count of meeting collection"
		result.Passed = true
		c, err := h.store.DB.Meeting().Count()
		result.Value = strconv.Itoa(c)
		if err != nil {
			result.Value = err.Error()
			result.Passed = false
		}
		return "meeting_count", result
	}
}

func NoncesStatusFunc(db *mgo.Database, collection string) debugstatus.CheckerFunc {
	return func() (key string, result debugstatus.CheckResult) {
		result.Name = "count of usso nonces collection"
		result.Passed = true
		c, err := db.C(collection).Count()
		result.Value = strconv.Itoa(c)
		if err != nil {
			result.Value = err.Error()
			result.Passed = false
		}
		return "nonce_count", result
	}
}

var NoncesStatus debugstatus.CheckerFunc

func (h *debugHandler) storePoolStatus() debugstatus.CheckerFunc {
	return func() (key string, result debugstatus.CheckResult) {
		result.Name = "Status of store limit pool (mgo)"
		result.Passed = true
		result.Value = "disabled"
		if h.h != nil && h.h.storePool != nil {
			info := h.h.storePool.Stats()
			result.Value = fmt.Sprintf("free: %d; limit: %d; size: %d", info.Free, info.Limit, info.Size)
			result.Passed = info.Size-info.Free < info.Limit
		}
		return "store_pool_status", result
	}
}
