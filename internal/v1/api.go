// Copyright 2014 Canonical Ltd.

package v1

import (
	"github.com/juju/httprequest"
	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/mempool"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

var logger = loggo.GetLogger("identity.internal.v1")

const (
	opAdmin         checkers.OperationChecker = "admin"
	opCreateAgent   checkers.OperationChecker = "create-agent"
	opCreateUser    checkers.OperationChecker = "create-user"
	opGetUser       checkers.OperationChecker = "get-user"
	opGetUserGroups checkers.OperationChecker = "get-user-groups"
)

// NewAPIHandler is an identity.NewAPIHandlerFunc.
func NewAPIHandler(p *store.Pool, params identity.ServerParams) ([]httprequest.Handler, error) {
	h := New(p, params)
	handlers := identity.ErrorMapper.Handlers(h.apiHandler)
	handlers = append(handlers, identity.ErrorMapper.Handlers(h.debugHandler)...)
	handlers = append(handlers, identity.ErrorMapper.Handlers(h.dischargeHandler)...)
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

func (h *Handler) getHandler(p httprequest.Params) (*handler, error) {
	store, err := h.storePool.Get()
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot get store", errgo.Any)
	}
	handler := h.handlerPool.Get().(*handler)
	handler.store = store
	handler.place = &place{store.Place}
	handler.params = p
	return handler, nil
}

type handler struct {
	h      *Handler
	params httprequest.Params
	store  *store.Store
	place  *place
}

func (h *handler) checkAdmin() error {
	return h.store.CheckACL(opAdmin, h.params.Request, []string{store.AdminGroup})
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
	h.store = nil
	h.place = nil
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
	hnd, err := h.getHandler(p)
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot create handler", errgo.Any)
	}
	return &apiHandler{
		handler: hnd,
	}, nil
}

type apiHandler struct {
	*handler
}

// debugHandler creates a per-request handler for endpoints relating to
// debug operations. This method conforms to the specification for
// https://godoc.org/github.com/juju/httprequest#ErrorMapper.Handlers and
// so can be used to automatically derive the list of endpoints to add to
// the router.
func (h *Handler) debugHandler(p httprequest.Params) (*debugHandler, error) {
	hnd, err := h.getHandler(p)
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot create handler", errgo.Any)
	}
	return &debugHandler{
		handler: hnd,
	}, nil
}

type debugHandler struct {
	*handler
}

// dischargeHandler creates a per-request handler for endpoints relating
// to discharge and login operations. This method conforms to the
// specification for
// https://godoc.org/github.com/juju/httprequest#ErrorMapper.Handlers and
// so can be used to automatically derive the list of endpoints to add to
// the router.
func (h *Handler) dischargeHandler(p httprequest.Params) (*dischargeHandler, error) {
	hnd, err := h.getHandler(p)
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot create handler", errgo.Any)
	}
	return &dischargeHandler{
		handler: hnd,
	}, nil
}

type dischargeHandler struct {
	*handler
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
		if idp.Name() == "usso" {
			logger.Debugf("adding USSO NoncesStatus to debug status")
			// Use the pool to grab the DB Session for use in debug status.
			// Put it back in the pool.
			s := h.storePool.GetNoLimit()
			db := s.DB.Session.DB("idp" + idp.Name())
			h.storePool.Put(s)
			NoncesStatus = NoncesStatusFunc(db, "nonces")
		}
	}
	return handlers
}
