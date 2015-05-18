// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"
	"strings"
	"time"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/params"
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

// checkThirdPartyCaveat checks the given caveat. This function is called by the httpbakery
// discharge logic. See httpbakery.AddDischargeHandler for futher details.
func (h *Handler) checkThirdPartyCaveat(req *http.Request, cavId, cav string) ([]checkers.Caveat, error) {
	err := h.auth.CheckAdminCredentials(req)
	var username string
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
		attrs, err := httpbakery.CheckRequest(h.svc, req, nil, checkers.New())
		if err != nil {
			return nil, h.needLoginError(cavId, cav, err.Error())
		}
		username = attrs["username"]
	}
	cond, args, err := checkers.ParseCaveat(cav)
	if err != nil {
		return nil, errgo.WithCausef(err, params.ErrBadRequest, "cannot parse caveat %q", cav)
	}
	switch cond {
	case "is-authenticated-user":
		return h.checkAuthenticatedUser(username)
	case "is-member-of":
		return h.checkMemberOfGroup(username, args)
	default:
		return nil, checkers.ErrCaveatNotRecognized
	}
}

// checkAuthenticatedUser checks a third-party caveat for "is-authenticated-user". Currently the discharge
// macaroon will only be created for users with admin credentials.
func (h *Handler) checkAuthenticatedUser(username string) ([]checkers.Caveat, error) {
	user, err := h.store.GetIdentity(params.Username(username))
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return []checkers.Caveat{
		checkers.DeclaredCaveat("uuid", user.UUID),
		checkers.DeclaredCaveat("username", user.Username),
		checkers.TimeBeforeCaveat(time.Now().Add(24 * time.Hour)),
	}, nil
}

// checkMemberOfGroup checks if user is member of any of the specified groups.
func (h *Handler) checkMemberOfGroup(username, targetGroups string) ([]checkers.Caveat, error) {
	groups := strings.Fields(targetGroups)

	user, err := h.store.GetIdentity(params.Username(username))
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	for _, userGroup := range user.Groups {
		for _, g := range groups {
			if userGroup == g {
				return nil, nil
			}
		}
	}
	return nil, errgo.Notef(err, "user is not a member of required groups")
}

// needLoginError returns an error suitable for returning
// from a discharge request that can only be satisfied
// if the user logs in.
func (h *Handler) needLoginError(cavId, caveat string, why string) error {
	// TODO(rog) If the user is already logged in (username != ""),
	// we should perhaps just return an error here.
	waitId, err := h.place.NewRendezvous(&thirdPartyCaveatInfo{
		CaveatId: cavId,
		Caveat:   caveat,
	})
	if err != nil {
		return errgo.Notef(err, "cannot make rendezvous")
	}
	return &httpbakery.Error{
		Message: why,
		Code:    httpbakery.ErrInteractionRequired,
		Info: &httpbakery.ErrorInfo{
			VisitURL: h.location + "/v1/login?waitid=" + waitId,
			WaitURL:  h.location + "/v1/wait?waitid=" + waitId,
		},
	}
}

type wait struct {
	WaitID string `httprequest:"waitid,form"`
}

// serveWait serves an HTTP endpoint that waits until a macaroon
// has been discharged, and returns the discharge macaroon.
func (h *Handler) serveWait(header http.Header, p httprequest.Params, w *wait) (*params.WaitResponse, error) {
	if w.WaitID == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "wait id parameter not found")
	}
	// TODO don't wait forever here.
	caveat, login, err := h.place.Wait(w.WaitID)
	if err != nil {
		return nil, errgo.Notef(err, "cannot wait")
	}
	if login.Error != nil {
		return nil, errgo.NoteMask(login.Error, "login failed", errgo.Any)
	}
	// We've now got the newly minted identity macaroon. Now
	// we want to check the third party caveat against the
	// identity that the user has logged in as, so add the
	// macaroon to the request and then go through the
	// same discharge checking that they would have gone
	// through even if they had gone through the web
	// login process.
	cookie, err := httpbakery.NewCookie(macaroon.Slice{login.IdentityMacaroon})
	if err != nil {
		return nil, errgo.Notef(err, "cannot make cookie")
	}
	p.AddCookie(cookie)
	checker := bakery.ThirdPartyCheckerFunc(func(cavId, cav string) ([]checkers.Caveat, error) {
		return h.checkThirdPartyCaveat(p.Request, cavId, cav)
	})
	m, err := h.svc.Discharge(checker, caveat.CaveatId)
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
	header.Add("Set-Cookie", cookie.String())

	return &params.WaitResponse{
		Macaroon: m,
	}, nil
}
