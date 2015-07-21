// Copyright 2015 Canonical Ltd.

package v1

import (
	"fmt"
	"net/http"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon-bakery.v1/httpbakery/agent"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/params"
)

// loginRequest is a request to start a login to the identity manager.
type loginRequest struct {
	httprequest.Route `httprequest:"GET /v1/login"`
	WaitID            string `httprequest:"waitid,form"`
}

// login handles the GET /v1/login endpoint that is used to log in to IdM.
func (h *dischargeHandler) Login(p httprequest.Params, lr *loginRequest) error {
	ussoOpenID, err := h.ussoOpenIDURL(lr.WaitID)
	if err != nil {
		return errgo.Notef(err, "cannot get openid login URL")
	}
	ussoOAuth, err := h.ussoOAuthURL(lr.WaitID)
	if err != nil {
		return errgo.Notef(err, "cannot get oauth login URL")
	}
	agentURL := h.agentLoginURL(lr.WaitID)
	user, key, err := agent.LoginCookie(p.Request)
	if err == nil {
		// We have some agent credentials, attempt an agent login.
		h.AgentLogin(p, &agentLoginRequest{
			WaitID: lr.WaitID,
			AgentLogin: params.AgentLogin{
				Username:  params.Username(user),
				PublicKey: key,
			},
		})
		return nil
	}
	if err != nil && errgo.Cause(err) != agent.ErrNoAgentLoginCookie {
		return errgo.Notef(err, "bad agent-login cookie")
	}
	// TODO should really be parsing the accept header properly here, but
	// it's really complicated http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.1
	// perhaps use http://godoc.org/bitbucket.org/ww/goautoneg for this.
	if p.Request.Header.Get("Accept") == "application/json" {
		err := httprequest.WriteJSON(p.Response, http.StatusOK, params.LoginMethods{
			Agent:          agentURL,
			Interactive:    ussoOpenID,
			UbuntuSSOOAuth: ussoOAuth,
		})
		if err != nil {
			return errgo.Notef(err, "cannot write login methods")
		}
		return nil
	}
	// Use the normal interactive login method.
	http.Redirect(p.Response, p.Request, ussoOpenID, http.StatusFound)
	return nil
}

func (h *dischargeHandler) loginID(w http.ResponseWriter, r *http.Request, userID string) {
	// We provide the user with a macaroon that they can use later
	// to prove to us that they have logged in. The macaroon is valid
	// for any operation that that user is allowed to perform.

	// TODO add expiry date and maybe more first party caveats to this.
	m, err := h.store.Service.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", userID),
	})
	if err != nil {
		h.loginFailure(w, r, userID, errgo.Notef(err, "cannot create macaroon"))
		return
	}
	if h.loginSuccess(w, r, userID, macaroon.Slice{m}) {
		fmt.Fprintf(w, "login successful as user %#v\n", userID)
	}
}

// loginSuccess is used by identity providers once they have determined that
// the login completed successfully.
func (h *dischargeHandler) loginSuccess(w http.ResponseWriter, r *http.Request, userID string, ms macaroon.Slice) bool {
	logger.Infof("successful login for user %s", userID)
	cookie, err := httpbakery.NewCookie(ms)
	if err != nil {
		h.loginFailure(w, r, userID, errgo.Notef(err, "cannot create cookie"))
		return false
	}
	http.SetCookie(w, cookie)
	r.ParseForm()
	waitId := r.Form.Get("waitid")
	if waitId != "" {
		if err := h.place.Done(waitId, &loginInfo{
			IdentityMacaroon: ms,
		}); err != nil {
			h.loginFailure(w, r, userID, errgo.Notef(err, "cannot complete rendezvous"))
			return false
		}
	}
	logger.Debugf("login complete for user %s", userID)
	return true
}

// loginFailure is used by identity providers once they have determined that
// the login has failed.
func (h *dischargeHandler) loginFailure(w http.ResponseWriter, r *http.Request, userID string, err error) {
	logger.Infof("login failed for %s: %s", userID, err)
	r.ParseForm()
	waitId := r.Form.Get("waitid")
	_, bakeryErr := httpbakery.ErrorToResponse(err)
	if waitId != "" {
		h.place.Done(waitId, &loginInfo{
			Error: bakeryErr.(*httpbakery.Error),
		})
	}
	identity.WriteError(w, err)
}
