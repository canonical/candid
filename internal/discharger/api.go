// Copyright 2014 Canonical Ltd.

// Pacakage discharger serves all of the endpoints related to discharging
// macaroon and logging in.
package discharger

import (
	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/juju/loggo"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/internal/auth/httpauth"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/monitoring"
)

var logger = loggo.GetLogger("identity.internal.dishcarger")

// NewAPIHandler is an identity.NewAPIHandlerFunc.
func NewAPIHandler(params identity.HandlerParams) ([]httprequest.Handler, error) {
	reqAuth := httpauth.New(params.Oven, params.Authorizer)
	place := &place{params.MeetingPlace}
	lc := &loginCompleter{
		params: params,
		place:  place,
	}
	if err := initIDPs(context.Background(), params, lc); err != nil {
		return nil, errgo.Mask(err)
	}
	checker := &thirdPartyCaveatChecker{
		params:  params,
		place:   place,
		reqAuth: reqAuth,
	}
	handlers := identity.ReqServer.Handlers(new(handlerParams{
		HandlerParams:  params,
		checker:        checker,
		loginCompleter: lc,
		place:          place,
		reqAuth:        reqAuth,
	}))
	d := httpbakery.NewDischarger(httpbakery.DischargerParams{
		Checker:         checker,
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
	handlers = append(handlers, idpHandlers(params)...)
	return handlers, nil
}

type handlerParams struct {
	identity.HandlerParams
	checker        *thirdPartyCaveatChecker
	loginCompleter *loginCompleter
	place          *place
	reqAuth        *httpauth.Authorizer
}

// new returns a function that creates new instances of the discharger API handler for a request.
func new(hParams handlerParams) func(p httprequest.Params, arg interface{}) (*handler, context.Context, error) {
	return func(p httprequest.Params, arg interface{}) (*handler, context.Context, error) {
		t := trace.New(p.Request.URL.Path, p.PathPattern)
		ctx := trace.NewContext(p.Context, t)
		ctx, close1 := hParams.Store.Context(ctx)
		ctx, close2 := hParams.MeetingStore.Context(ctx)
		hnd := &handler{
			params: hParams,
			trace:  t,
			monReq: monitoring.NewRequest(&p),
			close: func() {
				close2()
				close1()
			},
		}
		op := opForRequest(arg)
		logger.Debugf("opForRequest %#v -> %#v", arg, op)
		if op.Entity == "" {
			hnd.Close()
			return nil, nil, params.ErrUnauthorized
		}
		_, err := hParams.reqAuth.Auth(ctx, p.Request, op)
		if err != nil {
			hnd.Close()
			return nil, nil, errgo.Mask(err, errgo.Any)
		}
		return hnd, ctx, nil
	}
}

// A handler handles a request to a discharge related endpoint.
type handler struct {
	params handlerParams

	monReq monitoring.Request
	trace  trace.Trace
	close  func()
}

// Close implements io.Closer. httprequest will automatically call this
// once a request is complete.
func (h *handler) Close() error {
	h.close()
	h.trace.Finish()
	h.monReq.ObserveMetric()
	return nil
}

func idpHandlers(params identity.HandlerParams) []httprequest.Handler {
	var handlers []httprequest.Handler
	for _, idp := range params.IdentityProviders {
		idp := idp
		path := "/login/" + idp.Name() + "/*path"
		hfunc := newIDPHandler(params, idp)
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
