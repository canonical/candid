// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"
	"strings"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
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
func (c thirdPartyCaveatChecker) CheckThirdPartyCaveat(req *http.Request, ci *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
	h, err := c.handler.getHandler(
		httprequest.Params{
			Request: req,
		},
		req.URL.Path,
	)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer h.Close()
	return checkThirdPartyCaveat(h, req, ci)
}

// checkThirdPartyCaveat checks the given caveat. This function is called
// by the httpbakery discharge logic. See httpbakery.DischargeHandler
// for futher details.
func checkThirdPartyCaveat(h *handler, req *http.Request, ci *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
	err := h.store.CheckAdminCredentials(req)
	var username string
	var doc *mongodoc.Identity
	if err == nil {
		// Admin access granted. Find out what user the client wants
		// to discharge for.
		req.ParseForm()
		if username = req.Form.Get("discharge-for-user"); username == "" {
			return nil, errgo.WithCausef(nil, params.ErrBadRequest, "username not specified")
		}
	} else if errgo.Cause(err) != params.ErrNoAdminCredsProvided {
		return nil, errgo.WithCausef(err, params.ErrUnauthorized, "")
	} else {
		// No admin credentials provided - look for an identity macaroon.
		attrs, err := httpbakery.CheckRequest(h.store.Service, req, nil, checkers.New(
			store.UserHasPublicKeyChecker{Store: h.store, Identity: &doc},
			checkers.OperationChecker("discharge"),
		))
		if err != nil {
			return nil, needLoginError(h, &dischargeRequestInfo{
				CaveatId: ci.CaveatId,
				Caveat:   ci.Condition,
				Origin:   req.Header.Get("Origin"),
			}, err)
		}
		username = attrs["username"]
	}
	if doc == nil || string(doc.Username) != username {
		doc, err = h.store.GetIdentity(params.Username(username))
		if err != nil {
			return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
		}
	}
	cond, args, err := checkers.ParseCaveat(ci.Condition)
	if err != nil {
		return nil, errgo.WithCausef(err, params.ErrBadRequest, "cannot parse caveat %q", ci.Condition)
	}

	var cavs []checkers.Caveat
	switch cond {
	case "is-authenticated-user":
		cavs, err = checkAuthenticatedUser(doc)
	case "is-member-of":
		cavs, err = checkMemberOfGroup(doc, args)
	default:
		err = checkers.ErrCaveatNotRecognized
	}
	if err != nil {
		return nil, err
	}
	h.updateDischargeTime(params.Username(doc.Username))
	return cavs, nil
}

func (h *handler) updateDischargeTime(username params.Username) {
	err := h.store.UpdateIdentity(username, bson.D{{
		"$set", bson.D{{
			"lastdischarge", time.Now(),
		}},
	}})
	logger.Infof("unexpected error updating last discharge time: %s", err)
}

// checkAuthenticatedUser checks a third-party caveat for "is-authenticated-user". Currently the discharge
// macaroon will only be created for users with admin credentials.
func checkAuthenticatedUser(user *mongodoc.Identity) ([]checkers.Caveat, error) {
	return []checkers.Caveat{
		checkers.DeclaredCaveat("uuid", user.UUID),
		checkers.DeclaredCaveat("username", user.Username),
		checkers.TimeBeforeCaveat(time.Now().Add(24 * time.Hour)),
	}, nil
}

// checkMemberOfGroup checks if user is member of any of the specified groups.
func checkMemberOfGroup(user *mongodoc.Identity, targetGroups string) ([]checkers.Caveat, error) {
	groups := strings.Fields(targetGroups)
	for _, g := range groups {
		// A user is always a member of their own group.
		if g == user.Username {
			return nil, nil
		}
	}
	for _, userGroup := range user.Groups {
		for _, g := range groups {
			if userGroup == g {
				return nil, nil
			}
		}
	}
	return nil, errgo.Newf("user is not a member of required groups")
}

// needLoginError returns an error suitable for returning
// from a discharge request that can only be satisfied
// if the user logs in.
func needLoginError(h *handler, info *dischargeRequestInfo, why error) error {
	// TODO(rog) If the user is already logged in (username != ""),
	// we should perhaps just return an error here.
	waitId, err := h.place.NewRendezvous(info)
	if err != nil {
		return errgo.Notef(err, "cannot make rendezvous")
	}
	visitURL := h.serviceURL("/v1/login?waitid=" + waitId)
	waitURL := h.serviceURL("/v1/wait?waitid=" + waitId)
	return httpbakery.NewInteractionRequiredError(visitURL, waitURL, why, h.params.Request)
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
	Macaroon *macaroon.Macaroon

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
	// Ensure the identity macaroon can only be used from the same
	// origin as the original discharge request.
	err = login.IdentityMacaroon[0].AddFirstPartyCaveat(checkers.ClientOriginCaveat(reqInfo.Origin).Condition)
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
	cookie, err := httpbakery.NewCookie(login.IdentityMacaroon)
	if err != nil {
		return nil, errgo.Notef(err, "cannot make cookie")
	}
	cookie.Name = "macaroon-identity"
	p.Request.AddCookie(cookie)
	checker := bakery.ThirdPartyCheckerFunc(func(ci *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
		return checkThirdPartyCaveat(h.handler, p.Request, ci)
	})
	m, err := h.store.Service.Discharge(checker, reqInfo.CaveatId)
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
	DischargeToken *macaroon.Macaroon
}

// DischargeTokenForUser serves an HTTP endpoint that will create a discharge token for a user, if the
// origination has admin credentials only.
func (h *dischargeHandler) DischargeTokenForUser(p httprequest.Params, r *dischargeTokenForUserRequest) (dischargeTokenForUserResponse, error) {
	err := h.store.CheckAdminCredentials(p.Request)
	if err != nil {
		return dischargeTokenForUserResponse{}, errgo.WithCausef(err, params.ErrUnauthorized, "")
	}
	_, err = h.store.GetIdentity(r.Username)
	if err != nil {
		return dischargeTokenForUserResponse{}, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	m, err := h.store.Service.NewMacaroon(httpbakery.RequestVersion(p.Request), []checkers.Caveat{
		checkers.DeclaredCaveat("username", string(r.Username)),
		checkers.TimeBeforeCaveat(time.Now().Add(dischargeTokenDuration)),
	})
	if err != nil {
		return dischargeTokenForUserResponse{}, errgo.NoteMask(err, "cannot create discharge token", errgo.Any)
	}
	return dischargeTokenForUserResponse{
		DischargeToken: m,
	}, nil
}
