// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"encoding/base64"

	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
)

// waitTokenRequest is the request sent to the server to wait for logins to
// complete. Discharging caveats will normally be handled by the bakery
// it would be unusual to use this type directly in client software.
type waitTokenRequest struct {
	httprequest.Route `httprequest:"GET /wait-token"`
	DischargeID       string `httprequest:"did,form"`
}

// WaitToken waits on the rendezvous place for a discharge token and
// returns it.
func (h *handler) WaitToken(p httprequest.Params, req *waitTokenRequest) (*httpbakery.WaitTokenResponse, error) {
	_, dt, err := h.wait(p.Context, req.DischargeID)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return &httpbakery.WaitTokenResponse{
		Kind:    dt.Kind,
		Token64: base64.StdEncoding.EncodeToString(dt.Value),
	}, nil
}

// waitRequest is the request sent to the server to wait for logins to
// complete. Discharging caveats will normally be handled by the bakery
// it would be unusual to use this type directly in client software.
type waitRequest struct {
	httprequest.Route `httprequest:"GET /wait-legacy"`
	DischargeID       string `httprequest:"did,form"`
}

// Wait serves an HTTP endpoint that waits until a macaroon has been
// discharged, and returns the discharge macaroon.
// This is part of the legacy visit-wait protocol; newer clients will use WaitToken
// instead.
func (h *handler) WaitLegacy(p httprequest.Params, req *waitRequest) (*httpbakery.WaitResponse, error) {
	reqInfo, dt, err := h.wait(p.Context, req.DischargeID)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	m, err := bakery.Discharge(p.Context, bakery.DischargeParams{
		Id:     reqInfo.CaveatId,
		Caveat: reqInfo.Caveat,
		Key:    h.params.Key,
		Checker: bakery.ThirdPartyCaveatCheckerFunc(func(ctx context.Context, ci *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
			return h.params.checker.checkThirdPartyCaveat(ctx, httpbakery.ThirdPartyCaveatCheckerParams{
				Caveat:   ci,
				Request:  p.Request,
				Response: p.Response,
				Token:    dt,
			})
		}),
	})
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot discharge", errgo.Any)
	}
	return &httpbakery.WaitResponse{
		Macaroon: m,
	}, nil
}

func (h *handler) wait(ctx context.Context, dischargeID string) (*dischargeRequestInfo, *httpbakery.DischargeToken, error) {
	if dischargeID == "" {
		return nil, nil, errgo.WithCausef(nil, params.ErrBadRequest, "discharge id parameter not found")
	}
	// TODO don't wait forever here.
	reqInfo, login, err := h.params.place.Wait(ctx, dischargeID)
	if err != nil {
		return nil, nil, errgo.Notef(err, "cannot wait")
	}
	if login.Error != nil {
		return nil, nil, errgo.NoteMask(login.Error, "login failed", errgo.Any)
	}
	return reqInfo, login.DischargeToken, nil
}
