// Copyright 2014 Canonical Ltd.

package v1

import (
	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/juju/loggo"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/mempool"
	"github.com/CanonicalLtd/blues-identity/internal/monitoring"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

var logger = loggo.GetLogger("identity.internal.v1")

const (
	opAdmin         checkers.OperationChecker = "admin"
	opCreateAgent   checkers.OperationChecker = "create-agent"
	opCreateUser    checkers.OperationChecker = "create-user"
	opGetUser       checkers.OperationChecker = "get-user"
	opGetUserSSHKey checkers.OperationChecker = "get-user-ssh-key"
	opSetUserSSHKey checkers.OperationChecker = "set-user-ssh-key"
	opGetUserGroups checkers.OperationChecker = "get-user-groups"
	opSetUserGroups checkers.OperationChecker = "set-user-groups"
)

// TODO(mhilton) make the admin ACL configurable
var adminACL = []string{store.AdminUsername}

// NewAPIHandler is an identity.NewAPIHandlerFunc.
func NewAPIHandler(p *store.Pool, params identity.ServerParams) ([]httprequest.Handler, error) {
	h := New(p, params)
	handlers := identity.ErrorMapper.Handlers(h.apiHandler)
	handlers = append(handlers, identity.ErrorMapper.Handlers(h.dischargeHandler)...)
	d := httpbakery.NewDischarger(httpbakery.DischargerParams{
		Checker:         thirdPartyCaveatChecker{h},
		Key:             params.Key,
		ErrorToResponse: identity.ErrorMapper,
	})
	for _, h := range d.Handlers() {
		handlers = append(handlers, h)

		// also add the discharger endpoint at the legacy location.
		handlers = append(handlers, httprequest.Handler{
			Method: h.Method,
			Path:   "/v1/discharger" + h.Path,
			Handle: h.Handle,
		})
	}
	handlers = append(handlers, h.idpHandlers()...)
	return handlers, nil
}

// Handler handles the /v1 api requests. Handler implements http.Handler
type Handler struct {
	storePool   *store.Pool
	handlerPool mempool.Pool
	location    string
	idps        []idp.IdentityProvider
}

// New returns a new instance of the v1 API handler.
func New(p *store.Pool, params identity.ServerParams) *Handler {
	h := &Handler{
		storePool: p,
		location:  params.Location,
		idps:      params.IdentityProviders,
	}
	h.handlerPool.New = h.newHandler
	return h
}

func (h *Handler) newHandler() interface{} {
	return &handler{
		h: h,
	}
}

func (h *Handler) getHandler(p httprequest.Params, traceFamily string) (*handler, error) {
	t := trace.New(traceFamily, p.PathPattern)
	store, err := h.storePool.Get()
	if err != nil {
		// TODO(mhilton) consider logging inside the pool.
		t.LazyPrintf("cannot get store: %s", err)
		if errgo.Cause(err) != params.ErrServiceUnavailable {
			t.SetError()
		}
		t.Finish()
		return nil, errgo.NoteMask(err, "cannot get store", errgo.Any)
	}
	t.LazyPrintf("store acquired")
	handler := h.handlerPool.Get().(*handler)
	handler.store = store
	handler.place = &place{store.Place}
	handler.context = trace.NewContext(context.Background(), t)
	handler.params = p
	return handler, nil
}

type handler struct {
	h       *Handler
	params  httprequest.Params
	store   *store.Store
	place   *place
	context context.Context
}

func (h *handler) checkAdmin() error {
	return h.store.CheckACL(opAdmin, h.params.Request, adminACL)
}

// requestURL calculates the originally requested URL for the
// provided http.Request.
func (h *handler) requestURL() string {
	return h.h.location + h.params.Request.RequestURI
}

// serviceURL creates an external URL addressed to the specified path
// within the service.
func (h *handler) serviceURL(path string) string {
	return h.h.location + path
}

// Close implements io.Closer. httprequest will automatically call this
// once a request is complete.
func (h *handler) Close() error {
	h.h.storePool.Put(h.store)
	if t, ok := trace.FromContext(h.context); ok {
		t.LazyPrintf("store released")
		t.Finish()
	}
	h.store = nil
	h.place = nil
	h.context = nil
	h.params = httprequest.Params{}
	h.h.handlerPool.Put(h)
	return nil
}

// handler creates a per-request handler. This method conforms to the
// specification for
// https://godoc.org/github.com/juju/httprequest#ErrorMapper.Handlers and
// so can be used to automatically derive the list of endpoints to add to
// the router.
func (h *Handler) apiHandler(p httprequest.Params) (*apiHandler, error) {
	hnd, err := h.getHandler(p, "identity.internal.v1")
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot create handler", errgo.Any)
	}
	return &apiHandler{
		handler: hnd,
		monReq:  monitoring.NewRequest(&p),
	}, nil
}

type apiHandler struct {
	*handler
	monReq monitoring.Request
}

func (h *apiHandler) Close() error {
	err := h.handler.Close()
	h.monReq.ObserveMetric()
	return err
}

// dischargeHandler creates a per-request handler for endpoints relating
// to discharge and login operations. This method conforms to the
// specification for
// https://godoc.org/github.com/juju/httprequest#ErrorMapper.Handlers and
// so can be used to automatically derive the list of endpoints to add to
// the router.
func (h *Handler) dischargeHandler(p httprequest.Params) (*dischargeHandler, error) {
	hnd, err := h.getHandler(p, p.Request.URL.Path)
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot create handler", errgo.Any)
	}
	return &dischargeHandler{
		handler: hnd,
		monReq:  monitoring.NewRequest(&p),
	}, nil
}

type dischargeHandler struct {
	*handler
	monReq monitoring.Request
}

func (h *dischargeHandler) Close() error {
	err := h.handler.Close()
	h.monReq.ObserveMetric()
	return err
}

var errNotImplemented = errgo.Newf("method not implemented")

func (h *Handler) idpHandlers() []httprequest.Handler {
	var handlers []httprequest.Handler
	for _, idp := range h.idps {
		idp := idp
		path := "/v1/idp/" + idp.Name() + "/*path"
		hfunc := h.newIDPHandler(idp)
		handlers = append(handlers,
			httprequest.Handler{
				Method: "GET",
				Path:   path,
				Handle: hfunc,
			},
			httprequest.Handler{
				Method: "POST",
				Path:   path,
				Handle: hfunc,
			},
			httprequest.Handler{
				Method: "PUT",
				Path:   path,
				Handle: hfunc,
			},
		)
	}
	return handlers
}
