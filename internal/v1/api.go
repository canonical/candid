// Copyright 2014 Canonical Ltd.

package v1

import (
	"html/template"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/juju/loggo"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/mempool"
	"github.com/CanonicalLtd/blues-identity/internal/monitoring"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

var logger = loggo.GetLogger("identity.internal.v1")

// NewAPIHandler is an identity.NewAPIHandlerFunc.
func NewAPIHandler(p *store.Pool, params identity.ServerParams) ([]httprequest.Handler, error) {
	h := New(p, params)
	if err := h.initIDPs(); err != nil {
		return nil, errgo.Mask(err)
	}
	handlers := identity.ReqServer.Handlers(h.apiHandler)
	handlers = append(handlers, identity.ReqServer.Handlers(h.dischargeHandler)...)
	d := httpbakery.NewDischarger(httpbakery.DischargerParams{
		Checker:         thirdPartyCaveatChecker{h},
		Key:             params.Key,
		ErrorToResponse: identity.ReqServer.ErrorMapper,
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
	template    *template.Template
	key         *bakery.KeyPair
}

// New returns a new instance of the v1 API handler.
func New(p *store.Pool, params identity.ServerParams) *Handler {
	h := &Handler{
		storePool: p,
		location:  params.Location,
		idps:      params.IdentityProviders,
		template:  params.Template,
		key:       params.Key,
	}
	h.handlerPool.New = h.newHandler
	return h
}

func (h *Handler) newHandler() interface{} {
	return &handler{
		h: h,
	}
}

func (h *Handler) getAuthorizedHandler(p httprequest.Params, traceFamily string, req interface{}) (*handler, context.Context, error) {
	hnd, ctx, err := h.getHandler(p, traceFamily)
	if err != nil {
		return nil, nil, errgo.Mask(err)
	}
	op := opForRequest(req)
	logger.Infof("opForRequest %#v -> %#v", req, op)
	if op.Entity == "" {
		hnd.Close()
		return nil, nil, params.ErrUnauthorized
	}
	authInfo, err := hnd.store.Authorize(p.Context, p.Request, op)
	if err != nil {
		hnd.Close()
		return nil, nil, errgo.Mask(err, errgo.Any)
	}
	if authInfo.Identity != nil {
		id, ok := authInfo.Identity.(store.Identity)
		if !ok {
			hnd.Close()
			return nil, nil, errgo.Newf("unexpected identity type %T", authInfo.Identity)
		}
		ctx = contextWithIdentity(ctx, id)
	}
	return hnd, ctx, nil
}

func (h *Handler) getHandler(p httprequest.Params, traceFamily string) (*handler, context.Context, error) {
	ctx := p.Context
	t := trace.New(traceFamily, p.PathPattern)
	st := h.storePool.Get()
	handler := h.handlerPool.Get().(*handler)
	handler.store = st
	handler.place = &place{st.Place}
	handler.trace = t
	ctx = trace.NewContext(p.Context, t)
	ctx = store.ContextWithStore(ctx, st)
	return handler, ctx, nil
}

type handler struct {
	h     *Handler
	store *store.Store
	place *place
	trace trace.Trace
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
	h.trace.LazyPrintf("store released")
	h.trace.Finish()
	h.store = nil
	h.place = nil
	h.trace = nil
	h.h.handlerPool.Put(h)
	return nil
}

// handler creates a per-request handler. This method conforms to the
// specification for
// https://godoc.org/github.com/juju/httprequest#ErrorMapper.Handlers and
// so can be used to automatically derive the list of endpoints to add to
// the router.
func (h *Handler) apiHandler(p httprequest.Params, arg interface{}) (*apiHandler, context.Context, error) {
	hnd, ctx, err := h.getAuthorizedHandler(p, "identity.internal.v1", arg)
	if err != nil {
		return nil, nil, errgo.Mask(err, errgo.Any)
	}
	return &apiHandler{
		handler: hnd,
		monReq:  monitoring.NewRequest(&p),
	}, ctx, nil
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
func (h *Handler) dischargeHandler(p httprequest.Params, arg interface{}) (*dischargeHandler, context.Context, error) {
	hnd, ctx, err := h.getAuthorizedHandler(p, p.Request.URL.Path, arg)
	if err != nil {
		logger.Infof("cannot get authorized handler for discharge handler (pathpat %q; arg %#v): %v", p.PathPattern, arg, err)
		return nil, nil, errgo.Mask(err, errgo.Any)
	}
	logger.Infof("got authorized handler ok")
	return &dischargeHandler{
		handler: hnd,
		monReq:  monitoring.NewRequest(&p),
	}, ctx, nil
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

type identityKey struct{}

func contextWithIdentity(ctx context.Context, identity store.Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

func identityFromContext(ctx context.Context) store.Identity {
	id, _ := ctx.Value(identityKey{}).(store.Identity)
	return id
}
