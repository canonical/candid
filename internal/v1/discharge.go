// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"
	"strings"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

// verifiedUserInfo holds information provided by an
// external identity provider from a successful user login.
type verifiedUserInfo struct {
	User     string
	Nickname string
	FullName string
	Email    string
	Groups   []string
}

// checkThirdPartyCaveat checks the given caveat. This function is called
// by the httpbakery discharge logic. See httpbakery.AddDischargeHandler
// for futher details.
func (h *dischargeHandler) checkThirdPartyCaveat(req *http.Request, cavId, cav string) ([]checkers.Caveat, error) {
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
			return nil, h.needLoginError(&dischargeRequestInfo{
				CaveatId: cavId,
				Caveat:   cav,
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
	cond, args, err := checkers.ParseCaveat(cav)
	if err != nil {
		return nil, errgo.WithCausef(err, params.ErrBadRequest, "cannot parse caveat %q", cav)
	}
	switch cond {
	case "is-authenticated-user":
		return h.checkAuthenticatedUser(doc)
	case "is-member-of":
		return h.checkMemberOfGroup(doc, args)
	default:
		return nil, checkers.ErrCaveatNotRecognized
	}
}

// checkAuthenticatedUser checks a third-party caveat for "is-authenticated-user". Currently the discharge
// macaroon will only be created for users with admin credentials.
func (h *dischargeHandler) checkAuthenticatedUser(user *mongodoc.Identity) ([]checkers.Caveat, error) {
	return []checkers.Caveat{
		checkers.DeclaredCaveat("uuid", user.UUID),
		checkers.DeclaredCaveat("username", user.Username),
		checkers.TimeBeforeCaveat(time.Now().Add(24 * time.Hour)),
	}, nil
}

// checkMemberOfGroup checks if user is member of any of the specified groups.
func (h *dischargeHandler) checkMemberOfGroup(user *mongodoc.Identity, targetGroups string) ([]checkers.Caveat, error) {
	groups := strings.Fields(targetGroups)
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
func (h *dischargeHandler) needLoginError(info *dischargeRequestInfo, why error) error {
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
	//
	// Note: If there is more than one macaroon in the slice it is
	// conventional that the macaroon already has bound discharges,
	// and therefore the caveat cannot be added. This currently
	// doesn't matter because the only IDP that has a third party
	// caveat is agent login, which does not need origin protection.
	if len(login.IdentityMacaroon) == 1 {
		err = login.IdentityMacaroon[0].AddFirstPartyCaveat(checkers.ClientOriginCaveat(reqInfo.Origin).Condition)
		if err != nil {
			return nil, errgo.Notef(err, "cannot add origin caveat to identity macaroon")
		}
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
	checker := bakery.ThirdPartyCheckerFunc(func(cavId, cav string) ([]checkers.Caveat, error) {
		return h.checkThirdPartyCaveat(p.Request, cavId, cav)
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

// dischargeRequest is a request to create a macaroon that discharges the
// supplied third-party caveat. Discharging caveats will normally be
// handled by the bakery it would be unusual to use this type directly in
// client software.
type dischargeRequest struct {
	httprequest.Route `httprequest:"POST /discharge"`
	ID                string `httprequest:"id,form"`
}

// dischargeResponse contains macaroon that discharges a third-party
// caveat. Discharging caveats will normally be handled by the bakery it
// would be unusual to use this type directly in client software.
type dischargeResponse struct {
	Macaroon *macaroon.Macaroon `json:",omitempty"`
}

func (h *dischargeHandler) Discharge(p httprequest.Params, r *dischargeRequest) (*dischargeResponse, error) {
	m, err := h.store.Service.Discharge(
		bakery.ThirdPartyCheckerFunc(
			func(cavId, cav string) ([]checkers.Caveat, error) {
				return h.checkThirdPartyCaveat(p.Request, cavId, cav)
			},
		),
		r.ID,
	)
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot discharge", errgo.Any)
	}
	return &dischargeResponse{m}, nil
}

type legacyDischargeRequest struct {
	httprequest.Route `httprequest:"POST /v1/discharger/discharge"`
	dischargeRequest
}

// LegacyDischarge is the same as Discharge but served at the old
// location (/v1/discharger/discharge).
func (h *dischargeHandler) LegacyDischarge(p httprequest.Params, r *legacyDischargeRequest) (*dischargeResponse, error) {
	return h.Discharge(p, &r.dischargeRequest)
}

func (h *dischargeHandler) PublicKey(*params.PublicKeyRequest) (*params.PublicKeyResponse, error) {
	return &params.PublicKeyResponse{PublicKey: h.store.Service.PublicKey()}, nil
}

type legacyPublicKeyRequest struct {
	httprequest.Route `httprequest:"GET /v1/discharger/publickey"`
	params.PublicKeyRequest
}

// LegacyPublicKey is the same as PublicKey but served at the old
// location (/v1/discharger/publickey).
func (h *dischargeHandler) LegacyPublicKey(p *legacyPublicKeyRequest) (*params.PublicKeyResponse, error) {
	return h.PublicKey(&p.PublicKeyRequest)
}
