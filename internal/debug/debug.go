// Copyright 2016 Canonical Ltd.

package debug

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/juju/loggo"
	"github.com/juju/utils/debugstatus"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/version"
)

var logger = loggo.GetLogger("identity.internal.debug")

func NewAPIHandler(pool *store.Pool, params identity.ServerParams) ([]httprequest.Handler, error) {
	h := newDebugAPIHandler(pool, params)
	handlers := []httprequest.Handler{{
		Method: "GET",
		Path:   "/debug/login",
		Handle: h.login,
	}, {
		Method: "POST",
		Path:   "/debug/login",
		Handle: h.login,
	}}
	for _, hnd := range identity.ReqServer.Handlers(h.handler) {
		handlers = append(handlers, hnd)
	}
	return handlers, nil
}

func newDebugAPIHandler(pool *store.Pool, params identity.ServerParams) *debugAPIHandler {
	nonceDB := ""
	for _, idp := range params.IdentityProviders {
		if idp.Name() == "usso" {
			logger.Debugf("adding USSO NoncesStatus to debug status")
			nonceDB = "idp" + idp.Name()
		}
	}
	return &debugAPIHandler{
		pool:    pool,
		params:  params,
		nonceDB: nonceDB,
	}
}

type debugAPIHandler struct {
	pool    *store.Pool
	params  identity.ServerParams
	nonceDB string
}

func (h *debugAPIHandler) handler(p httprequest.Params) (*handler, context.Context, error) {
	return &handler{
		Handler: debugstatus.Handler{
			Version:           debugstatus.Version(version.VersionInfo),
			CheckPprofAllowed: h.checkLogin,
			CheckTraceAllowed: func(r *http.Request) (bool, error) {
				return false, h.checkLogin(r)
			},
		},
		h: h,
	}, p.Context, nil
}

type handler struct {
	debugstatus.Handler
	h *debugAPIHandler

	// store is set lazily when DebugStatus is called so that
	// debugstatus calls that don't require a store instance can
	// proceed without acquiring one.
	store *store.Store
}

// DebugStatus overrides Handler.DebugStatus to first get a store from
// the pool.
func (h *handler) DebugStatus(r *debugstatus.DebugStatusRequest) (map[string]debugstatus.CheckResult, error) {
	var err error
	h.store, err = h.h.pool.Get()
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrServiceUnavailable))
	}
	return h.check(), nil
}

// check implements the checkers function for use as Handler.Check.
func (h *handler) check() map[string]debugstatus.CheckResult {
	checks := []debugstatus.CheckerFunc{
		debugstatus.ServerStartTime,
		debugstatus.Connection(h.store.DB.Session),
		debugstatus.MongoCollections(h.store.DB),
		h.meetingStatus(),
		h.storePoolStatus(),
	}
	if h.h.nonceDB != "" {
		checks = append(checks, h.noncesStatus("nonces"))
	}
	return debugstatus.Check(checks...)
}

func (h *handler) meetingStatus() debugstatus.CheckerFunc {
	return func() (key string, result debugstatus.CheckResult) {
		result.Name = "count of meeting collection"
		result.Passed = true
		// TODO(mhilton) use a separate mechanism for this once
		// all the mongodb changes have been made.
		c, err := h.store.DB.C("meeting").Count()
		result.Value = strconv.Itoa(c)
		if err != nil {
			result.Value = err.Error()
			result.Passed = false
		}
		return "meeting_count", result
	}
}

func (h *handler) storePoolStatus() debugstatus.CheckerFunc {
	return func() (key string, result debugstatus.CheckResult) {
		result.Name = "Status of store limit pool (mgo)"
		result.Passed = true
		result.Value = "disabled"
		if h.h != nil && h.h.pool != nil {
			info := h.h.pool.Stats()
			result.Value = fmt.Sprintf("free: %d; limit: %d; size: %d", info.Free, info.Limit, info.Size)
			result.Passed = info.Size-info.Free < info.Limit
		}
		return "store_pool_status", result
	}
}

func (h *handler) noncesStatus(collection string) debugstatus.CheckerFunc {
	return func() (key string, result debugstatus.CheckResult) {
		result.Name = "count of usso nonces collection"
		result.Passed = true
		c, err := h.store.DB.Session.DB(h.h.nonceDB).C(collection).Count()
		result.Value = strconv.Itoa(c)
		if err != nil {
			result.Value = err.Error()
			result.Passed = false
		}
		return "nonce_count", result
	}
}

// Close implements io.Closer by returning any acquired store to the pool.
func (h *handler) Close() error {
	if h.store != nil {
		h.h.pool.Put(h.store)
	}
	return nil
}
