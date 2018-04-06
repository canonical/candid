// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package v1

import (
	"github.com/juju/loggo"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"

	"github.com/CanonicalLtd/candid/internal/auth"
	"github.com/CanonicalLtd/candid/internal/auth/httpauth"
	"github.com/CanonicalLtd/candid/internal/identity"
	"github.com/CanonicalLtd/candid/internal/monitoring"
)

var logger = loggo.GetLogger("candid.internal.v1")

// NewAPIHandler is an identity.NewAPIHandlerFunc.
func NewAPIHandler(params identity.HandlerParams) ([]httprequest.Handler, error) {
	return identity.ReqServer.Handlers(new(params)), nil
}

// new returns a function that will generate a new instance of the v1 API
// handler for a request.
func new(hParams identity.HandlerParams) func(p httprequest.Params, arg interface{}) (*handler, context.Context, error) {
	reqAuth := httpauth.New(hParams.Oven, hParams.Authorizer)
	return func(p httprequest.Params, arg interface{}) (*handler, context.Context, error) {
		t := trace.New("identity.internal.v1", p.PathPattern)
		ctx := trace.NewContext(p.Context, t)
		ctx, close1 := hParams.Store.Context(p.Context)
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
		authInfo, err := reqAuth.Auth(ctx, p.Request, op)
		if err != nil {
			hnd.Close()
			return nil, nil, errgo.Mask(err, errgo.Any)
		}
		if authInfo.Identity != nil {
			id, ok := authInfo.Identity.(*auth.Identity)
			if !ok {
				hnd.Close()
				return nil, nil, errgo.Newf("unexpected identity type %T", authInfo.Identity)
			}
			ctx = contextWithIdentity(ctx, id)
		}
		return hnd, ctx, nil
	}
}

// A handler is a handler for a request to a /v1 endpoint.
type handler struct {
	params identity.HandlerParams

	trace  trace.Trace
	monReq monitoring.Request
	close  func()
}

// Close implements io.Closer. httprequest will automatically call this
// once a request is complete.
func (h *handler) Close() error {
	if h.close != nil {
		h.close()
		h.close = nil
	}
	h.monReq.ObserveMetric()
	if h.trace != nil {
		h.trace.Finish()
		h.trace = nil
	}
	return nil
}

type identityKey struct{}

func contextWithIdentity(ctx context.Context, identity *auth.Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

func identityFromContext(ctx context.Context) *auth.Identity {
	id, _ := ctx.Value(identityKey{}).(*auth.Identity)
	return id
}
