// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package discharger serves all of the endpoints related to discharging
// macaroon and logging in.
package discharger

import (
	"context"

	"github.com/juju/loggo"
	"golang.org/x/net/trace"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"github.com/canonical/candid/v2/idp/idputil/secret"
	"github.com/canonical/candid/v2/internal/auth/httpauth"
	"github.com/canonical/candid/v2/internal/discharger/internal"
	"github.com/canonical/candid/v2/internal/identity"
	"github.com/canonical/candid/v2/internal/monitoring"
	"github.com/canonical/candid/v2/params"
)

var logger = loggo.GetLogger("candid.internal.discharger")

// NewAPIHandler is an identity.NewAPIHandlerFunc.
func NewAPIHandler(params identity.HandlerParams) ([]httprequest.Handler, error) {
	reqAuth := httpauth.New(params.Oven, params.Authorizer, params.APIMacaroonTimeout)
	place := &place{params.MeetingPlace}
	dt := &dischargeTokenCreator{
		params: params,
	}
	pidks, err := params.ProviderDataStore.KeyValueStore(context.Background(), "_provider_identity")
	if err != nil {
		return nil, errgo.Mask(err)
	}
	idstore := internal.NewIdentityStore(pidks, params.Store)
	vc := &visitCompleter{
		params:        params,
		identityStore: idstore,
		place:         place,
	}
	codec := secret.NewCodec(params.Key)
	err = initIDPs(context.Background(), initIDPParams{
		HandlerParams:         params,
		Codec:                 codec,
		DischargeTokenCreator: dt,
		VisitCompleter:        vc,
	})
	if err != nil {
		return nil, errgo.Mask(err)
	}
	checker := &thirdPartyCaveatChecker{
		params:  params,
		place:   place,
		reqAuth: reqAuth,
	}
	handlers := identity.ReqServer.Handlers(handlerCreator(handlerParams{
		HandlerParams:         params,
		checker:               checker,
		dischargeTokenCreator: dt,
		identityStore:         idstore,
		visitCompleter:        vc,
		place:                 place,
		reqAuth:               reqAuth,
		codec:                 codec,
	}))
	d := httpbakery.NewDischarger(httpbakery.DischargerParams{
		CheckerP:        checker,
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
	checker               *thirdPartyCaveatChecker
	dischargeTokenCreator *dischargeTokenCreator
	identityStore         *internal.IdentityStore
	visitCompleter        *visitCompleter
	place                 *place
	reqAuth               *httpauth.Authorizer
	codec                 *secret.Codec
}

// handlerCreator returns a function that creates new instances of the discharger API handler for a request.
func handlerCreator(hParams handlerParams) func(p httprequest.Params, arg interface{}) (*handler, context.Context, error) {
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
