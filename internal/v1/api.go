// Copyright 2014 Canonical Ltd.

package v1

import (
	"html/template"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient"
	"github.com/juju/idmclient/params"
	"github.com/juju/loggo"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"
	"gopkg.in/mgo.v2/bson"

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
	place       *place
}

// New returns a new instance of the v1 API handler.
func New(p *store.Pool, params identity.ServerParams) *Handler {
	h := &Handler{
		storePool: p,
		location:  params.Location,
		idps:      params.IdentityProviders,
		template:  params.Template,
		key:       params.Key,
		place:     &place{params.Place},
	}
	h.handlerPool.New = h.newHandler
	return h
}

func (h *Handler) newHandler() interface{} {
	return &handler{
		h: h,
	}
}

func (h *Handler) getAuthorizedHandler(p httprequest.Params, t trace.Trace, req interface{}) (*handler, context.Context, error) {
	hnd, ctx, err := h.getHandler(p.Context, t)
	if err != nil {
		t.Finish()
		return nil, nil, errgo.Mask(err)
	}
	op := opForRequest(req)
	logger.Infof("opForRequest %#v -> %#v", req, op)
	if op.Entity == "" {
		hnd.Close()
		return nil, nil, params.ErrUnauthorized
	}
	authInfo, err := hnd.store.Authorize(ctx, p.Request, op)
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

func (h *Handler) getHandler(ctx context.Context, t trace.Trace) (*handler, context.Context, error) {
	hnd := h.handlerPool.Get().(*handler)
	hnd.trace = t
	var err error
	hnd.store, err = h.storePool.Get()
	if err != nil {
		// TODO(mhilton) consider logging inside the pool.
		hnd.tracef(errgo.Cause(err) != params.ErrServiceUnavailable, "cannot get store: %s", err)
		h.handlerPool.Put(h)
		return nil, nil, errgo.NoteMask(err, "cannot get store", errgo.Any)
	}
	hnd.tracef(false, "store acquired")
	ctx = store.ContextWithStore(ctx, hnd.store)
	return hnd, ctx, nil
}

type handler struct {
	h     *Handler
	store *store.Store
	trace trace.Trace
}

// Close implements io.Closer. httprequest will automatically call this
// once a request is complete.
func (h *handler) Close() error {
	h.h.storePool.Put(h.store)
	h.store = nil
	h.tracef(false, "store released")
	if h.trace != nil {
		h.trace.Finish()
		h.trace = nil
	}
	h.h.handlerPool.Put(h)
	return nil
}

func (h *handler) tracef(setError bool, fmt string, args ...interface{}) {
	if h.trace == nil {
		return
	}
	h.trace.LazyPrintf(fmt, args...)
	if setError {
		h.trace.SetError()
	}
}

// serviceURL creates an external URL addressed to the specified path
// within the service.
func (h *handler) serviceURL(path string) string {
	return h.h.location + path
}

// completeLogin finishes a login attempt. A new macaroon will be minted
// with the given version, username and expiry and used to complete the
// rendezvous specified by the given waitid.
func (h *handler) completeLogin(ctx context.Context, waitid string, v bakery.Version, username params.Username, expiry time.Time) error {
	m, err := h.store.Bakery.Oven.NewMacaroon(
		ctx,
		v,
		expiry,
		[]checkers.Caveat{
			idmclient.UserDeclaration(string(username)),
		},
		bakery.LoginOp,
	)
	if err != nil {
		return errgo.Notef(err, "cannot mint identity macaroon")
	}
	if waitid != "" {
		if err := h.h.place.Done(ctx, waitid, &loginInfo{
			IdentityMacaroon: macaroon.Slice{m.M()},
		}); err != nil {
			return errgo.Notef(err, "cannot complete rendezvous")
		}
	}
	h.store.UpdateIdentity(username, bson.D{{"$set", bson.D{{"lastlogin", time.Now()}}}})
	return nil
}

// handler creates a per-request handler. This method conforms to the
// specification for
// https://godoc.org/github.com/juju/httprequest#ErrorMapper.Handlers and
// so can be used to automatically derive the list of endpoints to add to
// the router.
func (h *Handler) apiHandler(p httprequest.Params, arg interface{}) (*apiHandler, context.Context, error) {
	t := trace.New("identity.internal.v1", p.PathPattern)
	hnd, ctx, err := h.getAuthorizedHandler(p, t, arg)
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
	t := trace.New(p.Request.URL.Path, p.PathPattern)
	hnd, ctx, err := h.getAuthorizedHandler(p, t, arg)
	if err != nil {
		logger.Infof("cannot get authorized handler for discharge handler (pathpat %q; arg %#v): %v", p.PathPattern, arg, err)
		return nil, nil, errgo.Mask(err, errgo.Any)
	}
	logger.Infof("got authorized handler ok")
	return &dischargeHandler{
		handler: hnd,
		monReq:  monitoring.NewRequest(&p),
	}, trace.NewContext(ctx, t), nil
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
