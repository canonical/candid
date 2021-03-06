// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"context"
	"encoding/base64"
	"net/http"

	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v3/bakery"
	"gopkg.in/macaroon-bakery.v3/bakery/checkers"
	"gopkg.in/macaroon-bakery.v3/httpbakery"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/canonical/candid/v2/internal/auth"
	"github.com/canonical/candid/v2/params"
	"github.com/canonical/candid/v2/store"
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

// waitResponse is compatible with httpbakery.WaitResponse
// but adds a DischargeToken field for clients that can't
// use the identity cookie.
type waitResponse struct {
	httpbakery.WaitResponse

	// DischargeToken holds a macaroon that can be attached as
	// authorization for future discharge requests. This will also
	// be returned as a cookie.
	DischargeToken macaroon.Slice
}

// Wait serves an HTTP endpoint that waits until a macaroon has been
// discharged, and returns the discharge macaroon.
// This is part of the legacy visit-wait protocol; newer clients will use WaitToken
// instead.
func (h *handler) WaitLegacy(p httprequest.Params, req *waitRequest) (*waitResponse, error) {
	ctx := p.Context
	reqInfo, dt, err := h.wait(p.Context, req.DischargeID)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}

	// TODO we'd like to add a caveat to the discharge-token macaroon
	// to prevent it being moved between origins, but it's too late
	// because if it's an agent macaroon, it's already bound.
	//
	// however... why can't we just add the origin caveat when we create
	// the discharge token? the problem with that is that the callers of
	// DischargeToken don't necessarily have access to the original origin
	// (because they might be creating the token in response to a callback
	// from an external identity provider, for example).
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
	// Turn the discharge token into a macaroon so that
	// we can set it as a cookie.
	dtMacaroon, err := macaroonsFromDischargeToken(ctx, dt)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if err := setIdentityCookie(p.Response, dtMacaroon); err != nil {
		return nil, errgo.Mask(err)
	}
	return &waitResponse{
		WaitResponse: httpbakery.WaitResponse{
			Macaroon: m,
		},
		DischargeToken: dtMacaroon,
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
	id := store.Identity{
		ProviderID: login.ProviderID,
	}
	if err := h.params.Store.Identity(ctx, &id); err != nil {
		return nil, nil, errgo.Mask(err)
	}
	dt, err := h.params.dischargeTokenCreator.DischargeToken(ctx, &id)
	if err != nil {
		return nil, nil, errgo.Mask(err)
	}
	return reqInfo, dt, nil
}

// setIdentityCookie sets a cookie on the given response that will allow
// the user to log in without authenticating themselves. Note that when
// this is done on a wait or a discharge request, this is a security
// hole that means that any web site can obtain the capability to do
// arbitrary things as the logged in user. For the command line, though,
// we do want to return the cookie.
//
// TODO distinguish between the two cases by looking at the
// X-Requested-With header, return the identity cookie only when it's
// not present (i.e. when /wait is not called from an AJAX request).
func setIdentityCookie(resp http.ResponseWriter, m macaroon.Slice) error {
	cookie, err := httpbakery.NewCookie(auth.Namespace, m)
	if err != nil {
		return errgo.Notef(err, "cannot make cookie")
	}
	cookie.Path = "/"
	cookie.Name = "macaroon-identity"
	http.SetCookie(resp, cookie)
	return nil
}
