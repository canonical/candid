// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/names.v2"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/store"
)

const (
	// dischargeTokenDuration is the length of time for which a
	// discharge token is valid.
	dischargeTokenDuration = 6 * time.Hour
)

// thirdPartyCaveatChecker implements an
// httpbakery.ThirdPartyCaveatChecker for the identity service.
type thirdPartyCaveatChecker struct {
	handler *Handler
}

// CheckThirdPartyCaveat implements httpbakery.ThirdPartyCaveatChecker.
// It acquires a handler before checking the caveat, so that we have a
// database connection for the purpose.
func (c thirdPartyCaveatChecker) CheckThirdPartyCaveat(ctx context.Context, req *http.Request, ci *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
	h, ctx, err := c.handler.getHandler(
		httprequest.Params{
			Request: req,
			Context: ctx,
		},
		req.URL.Path,
	)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer h.Close()
	return checkThirdPartyCaveat(ctx, h, req, ci)
}

// checkThirdPartyCaveat checks the given caveat. This function is called
// by the httpbakery discharge logic. See httpbakery.DischargeHandler
// for futher details.
func checkThirdPartyCaveat(ctx context.Context, h *handler, req *http.Request, ci *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
	cond, args, err := checkers.ParseCaveat(string(ci.Condition))
	if err != nil {
		return nil, errgo.WithCausef(err, params.ErrBadRequest, "cannot parse caveat %q", ci.Condition)
	}
	domain := ""
	if c, err := req.Cookie("domain"); err == nil && names.IsValidUserDomain(c.Value) {
		domain = c.Value
	}
	switch cond {
	case "is-authenticated-user":
		if len(args) == 0 {
			break
		}
		if args[0] != '@' {
			return nil, checkers.ErrCaveatNotRecognized
		}
		if !names.IsValidUserDomain(args[1:]) {
			return nil, errgo.WithCausef(err, params.ErrBadRequest, "invalid domain %q", args[1:])
		}
		domain = args[1:]
		ctx = store.ContextWithRequiredDomain(ctx, domain)
	case "is-member-of":
	default:
		return nil, checkers.ErrCaveatNotRecognized
	}

	var identity store.Identity
	var invalidUserf func(err error) error
	if user := req.Form.Get("discharge-for-user"); user != "" {
		_, err := h.store.Authorize(ctx, req, store.GlobalOp(store.ActionDischargeFor))
		if err != nil {
			return nil, errgo.Mask(err, errgo.Is(params.ErrUnauthorized), isDischargeRequiredError)
		}
		invalidUserf = func(err error) error {
			return errgo.WithCausef(err, params.ErrBadRequest, "invalid username %q", user)
		}
		// We've bypassed the usual authorization logic, so make sure that the identity actually exists.
		if _, err := h.store.GetIdentity(params.Username(user)); err != nil {
			return nil, invalidUserf(err)
		}
		if err := store.CheckUserDomain(ctx, user); err != nil {
			return nil, invalidUserf(err)
		}
		identity = store.Identity(user)
	} else {
		invalidUserf = func(err error) error {
			return needLoginError(h, req, domain, &dischargeRequestInfo{
				Caveat:    ci.Caveat,
				CaveatId:  ci.Id,
				Condition: string(ci.Condition),
				Origin:    req.Header.Get("Origin"),
			}, err)
		}
		userInfo, err := h.store.Authorize(ctx, req, bakery.LoginOp)
		if err != nil {
			return nil, invalidUserf(err)
		}
		identity = userInfo.Identity.(store.Identity)
	}
	logger.Infof("authorization for %#v succeeded", identity)

	var cavs []checkers.Caveat
	switch cond {
	case "is-authenticated-user":
		cavs = []checkers.Caveat{
			idmclient.UserDeclaration(identity.Id()),
			checkers.TimeBeforeCaveat(time.Now().Add(24 * time.Hour)),
		}
	case "is-member-of":
		ok, err := identity.Allow(ctx, strings.Fields(args))
		if err != nil {
			return nil, errgo.Notef(err, "cannot check group membership")
		}
		if !ok {
			return nil, invalidUserf(errgo.Newf("user is not a member of required groups"))
		}
		// TODO should this be time-limited?
	}
	h.updateDischargeTime(params.Username(identity.Id()))
	return cavs, nil
}

func (h *handler) updateDischargeTime(username params.Username) {
	err := h.store.UpdateIdentity(username, bson.D{{
		"$set", bson.D{{
			"lastdischarge", time.Now(),
		}},
	}})
	if err != nil {
		logger.Infof("unexpected error updating last discharge time: %s", err)
	}
}

// needLoginError returns an error suitable for returning
// from a discharge request that can only be satisfied
// if the user logs in.
func needLoginError(h *handler, req *http.Request, domain string, info *dischargeRequestInfo, why error) error {
	// TODO(rog) If the user is already logged in (username != ""),
	// we should perhaps just return an error here.
	waitId, err := h.place.NewRendezvous(info)
	if err != nil {
		return errgo.Notef(err, "cannot make rendezvous")
	}
	visitURL := h.serviceURL("/v1/login?waitid=" + waitId)
	if domain != "" {
		visitURL += "&domain=" + url.QueryEscape(domain)
	}
	waitURL := h.serviceURL("/v1/wait?waitid=" + waitId)
	return httpbakery.NewInteractionRequiredError(visitURL, waitURL, why, req)
}

// waitRequest is the request sent to the server to wait for logins to
// complete. Discharging caveats will normally be handled by the bakery
// it would be unusual to use this type directly in client software.
type waitRequest struct {
	httprequest.Route `httprequest:"GET /v1/wait"`
	WaitID            string `httprequest:"waitid,form"`
}

// waitResponse holds the response from the wait endpoint. Discharging
// caveats will normally be handled by the bakery it would be unusual to
// use this type directly in client software.
type waitResponse struct {
	// Macaroon holds the acquired discharge macaroon.
	Macaroon *bakery.Macaroon

	// DischargeToken holds a macaroon that can be attached as
	// authorization for future discharge requests. This will also
	// be returned as a cookie.
	DischargeToken macaroon.Slice
}

// serveWait serves an HTTP endpoint that waits until a macaroon
// has been discharged, and returns the discharge macaroon.
func (h *dischargeHandler) Wait(p httprequest.Params, w *waitRequest) (*waitResponse, error) {
	if w.WaitID == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "wait id parameter not found")
	}
	// TODO don't wait forever here.
	reqInfo, login, err := h.place.Wait(w.WaitID)
	if err != nil {
		return nil, errgo.Notef(err, "cannot wait")
	}
	if login.Error != nil {
		return nil, errgo.NoteMask(login.Error, "login failed", errgo.Any)
	}
	// TODO we shouldn't need to manually resolve this caveat - the
	// reqInfo macaroon should contain a bakery.Macaroon not a macaroon slice.
	originCaveat := h.store.Bakery.Checker.Namespace().ResolveCaveat(httpbakery.ClientOriginCaveat(reqInfo.Origin))
	// Ensure the identity macaroon can only be used from the same
	// origin as the original discharge request.
	err = login.IdentityMacaroon[0].AddFirstPartyCaveat(originCaveat.Condition)
	if err != nil {
		return nil, errgo.Notef(err, "cannot add origin caveat to identity macaroon")
	}
	// We've now got the newly minted identity macaroon. Now
	// we want to check the third party caveat against the
	// identity that the user has logged in as, so add the
	// macaroon to the request and then go through the
	// same discharge checking that they would have gone
	// through even if they had gone through the web
	// login process.
	cookie, err := httpbakery.NewCookie(h.store.Bakery.Checker.Namespace(), login.IdentityMacaroon)
	if err != nil {
		return nil, errgo.Notef(err, "cannot make cookie")
	}
	cookie.Name = "macaroon-identity"
	p.Request.AddCookie(cookie)
	checker := bakery.ThirdPartyCaveatCheckerFunc(func(ctx context.Context, ci *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
		return checkThirdPartyCaveat(ctx, h.handler, p.Request, ci)
	})
	m, err := bakery.Discharge(p.Context, bakery.DischargeParams{
		Id:      reqInfo.CaveatId,
		Caveat:  reqInfo.Caveat,
		Key:     h.store.Bakery.Oven.Key(),
		Checker: checker,
	})
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot discharge", errgo.Any)
	}

	// Return the identity macaroon as a cookie in the wait
	// response. Note that this is a security hole that means that
	// any web site can obtain the capability to do arbitrary things
	// as the logged in user. For the command line, though, we do
	// want to return the cookie.
	//
	// TODO distinguish between the two cases by looking at the
	// X-Requested-With header, return the identity cookie only when
	// it's not present (i.e. when /wait is not called from an AJAX
	// request).
	cookie.Path = "/"
	http.SetCookie(p.Response, cookie)

	return &waitResponse{
		Macaroon:       m,
		DischargeToken: login.IdentityMacaroon,
	}, nil
}

// dischargeTokenForUserRequest is the request sent to get a discharge token for a user.
// This is only allowed for admin.
type dischargeTokenForUserRequest struct {
	httprequest.Route `httprequest:"GET /v1/discharge-token-for-user"`
	Username          params.Username `httprequest:"username,form"`
}

// dischargeTokenForUserResponse holds the response for the discharge token for user endpoint
// containing a discharge token for the user requested.
type dischargeTokenForUserResponse struct {
	DischargeToken *bakery.Macaroon
}

// DischargeTokenForUser serves an HTTP endpoint that will create a discharge token for a user.
func (h *dischargeHandler) DischargeTokenForUser(p httprequest.Params, r *dischargeTokenForUserRequest) (dischargeTokenForUserResponse, error) {
	_, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return dischargeTokenForUserResponse{}, errgo.NoteMask(err, "cannot get identity", errgo.Is(params.ErrNotFound))
	}
	m, err := h.store.Bakery.Oven.NewMacaroon(
		p.Context,
		httpbakery.RequestVersion(p.Request),
		time.Now().Add(dischargeTokenDuration),
		[]checkers.Caveat{
			idmclient.UserDeclaration(string(r.Username)),
		},
		bakery.LoginOp,
	)
	if err != nil {
		return dischargeTokenForUserResponse{}, errgo.NoteMask(err, "cannot create discharge token", errgo.Any)
	}
	return dischargeTokenForUserResponse{
		DischargeToken: m,
	}, nil
}

func isDischargeRequiredError(err error) bool {
	cause, ok := errgo.Cause(err).(*httpbakery.Error)
	return ok && cause.Code == httpbakery.ErrDischargeRequired
}
