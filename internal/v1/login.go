// Copyright 2015 Canonical Ltd.

package v1

import (
	"fmt"
	"net/http"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/params"
)

// login handles the GET /v1/login endpoint that is used to log in to IdM.
func (h *Handler) login(w http.ResponseWriter, p httprequest.Params) error {
	r := p.Request
	r.ParseForm()
	waitId := r.Form.Get("waitid")
	ussoOpenID, err := h.provider.openIDURL(waitId)
	if err != nil {
		return errgo.Notef(err, "cannot get openid login URL")
	}
	ussoOAuth, err := h.provider.oauthURL(waitId)
	if err != nil {
		return errgo.Notef(err, "cannot get oauth login URL")
	}
	// TODO should really be parsing the accept header properly here, but
	// it's really complicated http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.1
	// perhaps use http://godoc.org/bitbucket.org/ww/goautoneg for this.
	if p.Request.Header.Get("Accept") == "application/json" {
		err := httprequest.WriteJSON(w, http.StatusOK, params.LoginMethods{
			Interactive:    ussoOpenID,
			UbuntuSSOOAuth: ussoOAuth,
		})
		if err != nil {
			return errgo.Notef(err, "cannot write login methods")
		}
		return nil
	}
	http.Redirect(w, r, ussoOpenID, http.StatusFound)
	return nil
}

// loginSuccess is used by identity providers once they have determined that
// the login completed successfully.
func (h *Handler) loginSuccess(w http.ResponseWriter, r *http.Request, userID string) {
	r.ParseForm()
	waitId := r.Form.Get("waitid")
	// We provide the user with a macaroon that they can use later
	// to prove to us that they have logged in. The macaroon is valid
	// for any operation that that user is allowed to perform.

	// TODO add expiry date and maybe more first party caveats to this.
	m, err := h.svc.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", userID),
		httpbakery.SameClientIPAddrCaveat(r),
	})
	if err != nil {
		h.loginFailure(w, r, errgo.Notef(err, "cannot create macaroon"))
		return
	}
	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
	if err != nil {
		h.loginFailure(w, r, errgo.Notef(err, "cannot create cookie"))
		return
	}
	http.SetCookie(w, cookie)
	if waitId != "" {
		if err := h.place.Done(waitId, &loginInfo{
			IdentityMacaroon: m,
		}); err != nil {
			h.loginFailure(w, r, errgo.Notef(err, "cannot complete rendezvous"))
			return
		}
	}
	fmt.Fprintf(w, "login successful as user %#v\n", userID)
}

// loginFailure is used by identity providers once they have determined that
// the login has failed.
func (h *Handler) loginFailure(w http.ResponseWriter, r *http.Request, err error) {
	r.ParseForm()
	waitId := r.Form.Get("waitid")
	_, bakeryErr := httpbakery.ErrorToResponse(err)
	if waitId != "" {
		h.place.Done(waitId, &loginInfo{
			Error: bakeryErr.(*httpbakery.Error),
		})
	}
	writeError(w, err)
}
