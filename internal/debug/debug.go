// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package debug

import (
	"net/http"

	"github.com/juju/loggo"
	"github.com/juju/utils/debugstatus"
	"golang.org/x/net/context"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/candid/internal/identity"
	"github.com/CanonicalLtd/candid/version"
)

var logger = loggo.GetLogger("candid.internal.debug")

var stdCheckers = []debugstatus.CheckerFunc{
	debugstatus.ServerStartTime,
}

func NewAPIHandler(params identity.HandlerParams) ([]httprequest.Handler, error) {
	h := newDebugAPIHandler(params)
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

func newDebugAPIHandler(params identity.HandlerParams) *debugAPIHandler {
	h := &debugAPIHandler{
		key:      params.Key,
		location: params.Location,
		teams:    params.DebugTeams,
	}
	checkerFuncs := append(stdCheckers, params.DebugStatusCheckerFuncs...)
	h.hnd = debugstatus.Handler{
		Check: func(ctx context.Context) map[string]debugstatus.CheckResult {
			// TODO (mhilton) re-instate meeting status checks.
			return debugstatus.Check(ctx, checkerFuncs...)
		},
		Version:           debugstatus.Version(version.VersionInfo),
		CheckPprofAllowed: h.checkLogin,
		CheckTraceAllowed: func(r *http.Request) (bool, error) {
			return false, h.checkLogin(r)
		},
	}
	return h
}

type debugAPIHandler struct {
	key      *bakery.KeyPair
	location string
	teams    []string
	hnd      debugstatus.Handler
}

func (h *debugAPIHandler) handler(p httprequest.Params) (*debugstatus.Handler, context.Context, error) {
	return &h.hnd, p.Context, nil
}
