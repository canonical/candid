// Copyright 2014 Canonical Ltd.

package v1

import (
	"fmt"
	"net/http"
	"time"

	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v0/bakery"
	"gopkg.in/macaroon-bakery.v0/bakery/checkers"
	"gopkg.in/macaroon-bakery.v0/httpbakery"
	"gopkg.in/macaroon.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/router"
	"github.com/CanonicalLtd/blues-identity/params"
)

// verifiedUserInfo holds information provided by an
// external identity provider from a successful user login.
type verifiedUserInfo struct {
	User     string
	Nickname string
	FullName string
	Email    string
	Teams    string
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
	switch cav {
	case "is-authenticated-user":
		return h.checkAuthenticatedUser(username)
	default:
		return nil, checkers.ErrCaveatNotRecognized
	}
}

// checkAuthenticatedUser checks a third-party caveat for "is-authenticated-user". Currently the discharge
// macaroon will only be created for users with admin credentials.
func (h *Handler) checkAuthenticatedUser(username string) ([]checkers.Caveat, error) {
	var user mongodoc.Identity
	if err := h.store.DB.Identities().Find(bson.M{"username": username}).One(&user); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return nil, errgo.WithCausef(err, params.ErrForbidden, "user %q not found", username)
		}
	}
	return []checkers.Caveat{
		checkers.DeclaredCaveat("uuid", user.UUID),
		checkers.DeclaredCaveat("username", user.UserName),
		checkers.TimeBeforeCaveat(time.Now().Add(24 * time.Hour)),
	}, nil
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

	// Could potentially bounce to a "choose login method" page
	// here rather than going straight to a single chosen provider.
	loginURL, err := h.provider.loginURL(h.idProviderBaseURL(), waitId)
	if err != nil {
		return errgo.Mask(err)
	}
	return &httpbakery.Error{
		Message: why,
		Code:    httpbakery.ErrInteractionRequired,
		Info: &httpbakery.ErrorInfo{
			VisitURL: loginURL,
			WaitURL:  "/v1/wait?waitid=" + waitId,
		},
	}
}

// loginCallbackHandler returns a handler which handles a callback
// from the given id provider, calling idp.login to obtain information
// on the request that was made.
func (h *Handler) loginCallbackHandler(idp idProvider) http.Handler {
	return router.HandleErrors(func(w http.ResponseWriter, req *http.Request) error {
		return h.loginCallback(w, req, idp)
	})
}

// loginCallback is a generalised entry point for external identity providers.
// It handles a callback request from an external identity provider
// and calls idP.login to determine the user's information
// from the callback request.
func (h *Handler) loginCallback(w http.ResponseWriter, req *http.Request, idp idProvider) error {
	req.ParseForm()
	waitId := req.Form.Get("waitid")
	if waitId == "" {
		return errgo.New("wait id not found in callback")
	}
	m, info, err := h.loginCallback1(w, req, waitId, idp)
	if err != nil {
		_, bakeryErr := httpbakery.ErrorToResponse(err)
		h.place.Done(waitId, &loginInfo{
			Error: bakeryErr.(*httpbakery.Error),
		})
		return errgo.Notef(err, "login failed")
	}
	if err := h.place.Done(waitId, &loginInfo{
		IdentityMacaroon: m,
	}); err != nil {
		return errgo.Notef(err, "cannot complete rendezvous")
	}
	fmt.Fprintf(w, "login successful as user %#v\n", info)
	return nil
}

// loginCallback1 is the inner implementation of loginCallback.
// It does everything except reply to the wait request.
func (h *Handler) loginCallback1(
	w http.ResponseWriter,
	req *http.Request,
	waitId string,
	idp idProvider,
) (*macaroon.Macaroon, *verifiedUserInfo, error) {
	info, err := idp.verifyCallback(w, req)
	if err != nil {
		return nil, nil, errgo.Mask(err, errgo.Any)
	}
	if info.User == "" {
		return nil, nil, errgo.New("no user found in openid callback")
	}
	if info.Nickname == "" {
		return nil, nil, errgo.New("no nickname found in openid callback")
	}
	// Create the user information if necessary.
	if err := h.store.UpsertIdentity(&mongodoc.Identity{
		UserName:   info.Nickname,
		ExternalID: info.User,
		Email:      info.Email,
		FullName:   info.FullName,
	}); err != nil {
		return nil, nil, errgo.Mask(err)
	}

	// We provide the user with a macaroon that they can use later
	// to prove to us that they have logged in. The macaroon is valid
	// for any operation that that user is allowed to perform.

	// TODO add expiry date and maybe more first party caveats to this.
	m, err := h.svc.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", info.Nickname),
		httpbakery.SameClientIPAddrCaveat(req),
	})
	if err != nil {
		return nil, nil, errgo.Notef(err, "cannot mint macaroon")
	}
	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
	if err != nil {
		return nil, nil, errgo.Notef(err, "cannot create cookie")
	}
	http.SetCookie(w, cookie)
	return m, info, nil
}

// serveWait serves an HTTP endpoint that waits until a macaroon
// has been discharged, and returns the discharge macaroon.
func (h *Handler) serveWait(header http.Header, req *http.Request) (interface{}, error) {
	req.ParseForm()
	waitId := req.Form.Get("waitid")
	if waitId == "" {
		return nil, errgo.New("wait id parameter not found")
	}
	// TODO don't wait forever here.
	caveat, login, err := h.place.Wait(waitId)
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
	req.AddCookie(cookie)
	checker := bakery.ThirdPartyCheckerFunc(func(cavId, cav string) ([]checkers.Caveat, error) {
		return h.checkThirdPartyCaveat(req, cavId, cav)
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

	return params.WaitResponse{
		Macaroon: m,
	}, nil
}
