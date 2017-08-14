// Copyright 2014 Canonical Ltd.

package discharger

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/names.v2"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"

	"github.com/CanonicalLtd/blues-identity/internal/auth"
	"github.com/CanonicalLtd/blues-identity/internal/auth/httpauth"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/store"
)

const (
	// dischargeTokenDuration is the length of time for which a
	// discharge token is valid.
	dischargeTokenDuration = 6 * time.Hour
)

// thirdPartyCaveatChecker implements an
// httpbakery.ThirdPartyCaveatChecker for the identity service.
type thirdPartyCaveatChecker struct {
	params  identity.HandlerParams
	reqAuth *httpauth.Authorizer
	place   *place
}

// CheckThirdPartyCaveat implements httpbakery.ThirdPartyCaveatChecker.
// It acquires a handler before checking the caveat, so that we have a
// database connection for the purpose.
func (c *thirdPartyCaveatChecker) CheckThirdPartyCaveat(ctx context.Context, req *http.Request, ci *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
	t := trace.New(req.URL.Path, "")
	defer t.Finish()
	return c.checkThirdPartyCaveat(trace.NewContext(ctx, t), req, ci)
}

// checkThirdPartyCaveat checks the given caveat. This function is called
// by the httpbakery discharge logic. See httpbakery.DischargeHandler
// for futher details.
func (c *thirdPartyCaveatChecker) checkThirdPartyCaveat(ctx context.Context, req *http.Request, ci *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
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
		ctx = auth.ContextWithRequiredDomain(ctx, domain)
	case "is-member-of":
	default:
		return nil, checkers.ErrCaveatNotRecognized
	}

	var identity *auth.Identity
	var invalidUserf func(err error) error
	if user := req.Form.Get("discharge-for-user"); user != "" {
		_, err := c.reqAuth.Auth(ctx, req, auth.GlobalOp(auth.ActionDischargeFor))
		if err != nil {
			return nil, errgo.Mask(err, errgo.Is(params.ErrUnauthorized), isDischargeRequiredError)
		}
		invalidUserf = func(err error) error {
			return errgo.WithCausef(err, params.ErrBadRequest, "invalid username %q", user)
		}
		identity, err = c.params.Authorizer.Identity(ctx, user)
		if err != nil {
			return nil, invalidUserf(err)
		}
		if err := auth.CheckUserDomain(ctx, user); err != nil {
			return nil, invalidUserf(err)
		}
	} else {
		invalidUserf = func(err error) error {
			return c.needLoginError(ctx, req, domain, &dischargeRequestInfo{
				Caveat:    ci.Caveat,
				CaveatId:  ci.Id,
				Condition: string(ci.Condition),
				Origin:    req.Header.Get("Origin"),
			}, err)
		}
		userInfo, err := c.reqAuth.Auth(ctx, req, bakery.LoginOp)
		if err != nil {
			return nil, invalidUserf(err)
		}
		identity = userInfo.Identity.(*auth.Identity)
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
	c.updateDischargeTime(ctx, identity.Id())
	return cavs, nil
}

func (c *thirdPartyCaveatChecker) updateDischargeTime(ctx context.Context, username string) {
	err := c.params.Store.UpdateIdentity(
		ctx,
		&store.Identity{
			Username:      username,
			LastDischarge: time.Now(),
		}, store.Update{
			store.LastDischarge: store.Set,
		},
	)
	if err != nil {
		logger.Infof("unexpected error updating last discharge time: %s", err)
	}
}

// needLoginError returns an error suitable for returning
// from a discharge request that can only be satisfied
// if the user logs in.
func (c *thirdPartyCaveatChecker) needLoginError(ctx context.Context, req *http.Request, domain string, info *dischargeRequestInfo, why error) error {
	// TODO(rog) If the user is already logged in (username != ""),
	// we should perhaps just return an error here.
	waitId, err := c.place.NewRendezvous(ctx, info)
	if err != nil {
		return errgo.Notef(err, "cannot make rendezvous")
	}
	visitURL := c.params.Location + "/login?waitid=" + waitId
	if domain != "" {
		visitURL += "&domain=" + url.QueryEscape(domain)
	}
	waitURL := c.params.Location + "/wait?waitid=" + waitId
	return httpbakery.NewInteractionRequiredError(visitURL, waitURL, why, req)
}

// waitRequest is the request sent to the server to wait for logins to
// complete. Discharging caveats will normally be handled by the bakery
// it would be unusual to use this type directly in client software.
type waitRequest struct {
	httprequest.Route `httprequest:"GET /wait"`
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
func (h *handler) Wait(p httprequest.Params, w *waitRequest) (*waitResponse, error) {
	if w.WaitID == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "wait id parameter not found")
	}
	// TODO don't wait forever here.
	reqInfo, login, err := h.params.place.Wait(p.Context, w.WaitID)
	if err != nil {
		return nil, errgo.Notef(err, "cannot wait")
	}
	if login.Error != nil {
		return nil, errgo.NoteMask(login.Error, "login failed", errgo.Any)
	}
	// TODO we shouldn't need to manually resolve this caveat - the
	// reqInfo macaroon should contain a bakery.Macaroon not a macaroon slice.
	originCaveat := auth.Namespace.ResolveCaveat(httpbakery.ClientOriginCaveat(reqInfo.Origin))
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
	cookie, err := httpbakery.NewCookie(auth.Namespace, login.IdentityMacaroon)
	if err != nil {
		return nil, errgo.Notef(err, "cannot make cookie")
	}
	cookie.Name = "macaroon-identity"
	p.Request.AddCookie(cookie)
	m, err := bakery.Discharge(p.Context, bakery.DischargeParams{
		Id:     reqInfo.CaveatId,
		Caveat: reqInfo.Caveat,
		Key:    h.params.Key,
		Checker: bakery.ThirdPartyCaveatCheckerFunc(func(ctx context.Context, ci *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
			return h.params.checker.checkThirdPartyCaveat(ctx, p.Request, ci)
		}),
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

func isDischargeRequiredError(err error) bool {
	cause, ok := errgo.Cause(err).(*httpbakery.Error)
	return ok && cause.Code == httpbakery.ErrDischargeRequired
}
