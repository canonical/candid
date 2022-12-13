// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery/agent"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"

	"github.com/canonical/candid/idp/idputil"
	"github.com/canonical/candid/params"
	"github.com/canonical/candid/store"
)

// legacyLoginRequest is a request to start a login to the identity manager
// using the legacy visit-wait protocol.
type legacyLoginRequest struct {
	httprequest.Route `httprequest:"GET /login-legacy"`
	Domain            string `httprequest:"domain,form"`
	DischargeID       string `httprequest:"did,form"`
}

// LoginLegacy handles the GET /login-legacy endpoint that is used to log in to Candid
// when the legacy visit-wait protocol is used.
func (h *handler) LoginLegacy(p httprequest.Params, req *legacyLoginRequest) error {
	// We should really be parsing the accept header properly here, but
	// it's really complicated http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.1
	// perhaps use http://godoc.org/bitbucket.org/ww/goautoneg for this.
	// Probably not worth it now that it's only part of the legacy protocol.
	if p.Request.Header.Get("Accept") == "application/json" {
		methods := map[string]string{"agent": legacyAgentURL(h.params.Location, req.DischargeID)}
		for _, idp := range h.params.IdentityProviders {
			methods[idp.Name()] = idp.URL(req.DischargeID)
		}
		err := httprequest.WriteJSON(p.Response, http.StatusOK, methods)
		if err != nil {
			return errgo.Notef(err, "cannot write login methods")
		}
		return nil
	}

	_, _, err := agent.LoginCookie(p.Request)
	if errgo.Cause(err) != agent.ErrNoAgentLoginCookie {

		resp, err := h.LegacyAgentLogin(p, &legacyAgentLoginRequest{
			DischargeID: req.DischargeID,
		})
		if err != nil {
			return errgo.Mask(err, errgo.Any)
		}
		return httprequest.WriteJSON(p.Response, http.StatusOK, resp)
	}
	if err != nil && errgo.Cause(err) != agent.ErrNoAgentLoginCookie {
		return errgo.Notef(err, "bad agent-login cookie")
	}
	return h.Login(p, (*loginRequest)(req))
}

// loginRequest is a request to start a login to the identity manager.
type loginRequest struct {
	httprequest.Route `httprequest:"GET /login"`
	Domain            string `httprequest:"domain,form"`
	DischargeID       string `httprequest:"did,form"`
}

// Login handles the GET /v1/login endpoint that is used to log in to Candid.
// when an interactive visit-wait protocol has been chosen by the client.
func (h *handler) Login(p httprequest.Params, req *loginRequest) error {
	// Store the requested discharge ID in a session cookie so that
	// when the redirect comes back to login-complete we know the
	// login was initiated in this session.
	cookiePath := idputil.CookiePathRelativeToLocation("/login-complete", h.params.Location, h.params.SkipLocationForCookiePaths)
	state, err := h.params.codec.SetCookie(p.Response, waitCookieName, cookiePath, waitState{
		DischargeID: req.DischargeID,
	})
	if err != nil {
		return errgo.Mask(err)
	}
	v := url.Values{
		"state":     {state},
		"return_to": {h.params.Location + "/login-complete"},
	}
	if req.Domain != "" {
		v.Set("domain", req.Domain)
	}
	http.Redirect(p.Response, p.Request, h.params.Location+"/login-redirect?"+v.Encode(), http.StatusTemporaryRedirect)
	return nil
}

// redirectLoginRequest is a request to start a redirect based login to
// the identity server.
type redirectLoginRequest struct {
	httprequest.Route `httprequest:"GET /login-redirect"`

	// Domain holdes the requested identity provider domain, if any.
	Domain string `httprequest:"domain,form"`

	// ReturnTo holds the URL that the service will redirect to when
	// the login attempt is complete.
	ReturnTo string `httprequest:"return_to,form"`

	// State holds an opaque token that will be sent back to the
	// requesting service so the service can check that it initiated
	// the original login request.
	State string `httprequest:"state,form"`
}

// RedirectLogin handles starting a redirect based login request for a
// domain (if specified). It produces a page with the possible choices of
// identity provider which the user must then choose to start the login
// process.
func (h *handler) RedirectLogin(p httprequest.Params, req *redirectLoginRequest) error {
	cookiePath := idputil.CookiePathRelativeToLocation(idputil.LoginCookiePath, h.params.Location, h.params.SkipLocationForCookiePaths)
	state, err := h.params.codec.SetCookie(p.Response, idputil.LoginCookieName, cookiePath, idputil.LoginState{
		ReturnTo: req.ReturnTo,
		State:    req.State,
		Expires:  time.Now().Add(15 * time.Minute),
	})
	if err != nil {
		return errgo.Mask(err)
	}
	return errgo.Mask(h.authChoice(p.Response, p.Request, state, req.Domain, "", false))
}

func (h *handler) authChoice(w http.ResponseWriter, req *http.Request, state, domain, errorMessage string, useEmail bool) error {
	// Find all the possible login methods.
	var allIDPs []params.IDPChoiceDetails
	var idps []params.IDPChoiceDetails
	for _, idp := range h.params.IdentityProviders {
		if !idp.Interactive() {
			continue
		}
		choice := params.IDPChoiceDetails{
			Name:        idp.Name(),
			Domain:      idp.Domain(),
			Description: idp.Description(),
			Icon:        idp.IconURL(),
			URL:         idp.URL(state),
		}
		if !idp.Hidden() {
			allIDPs = append(allIDPs, choice)
		}
		if domain != "" && idp.Domain() == domain {
			idps = append(idps, choice)
		}
	}
	if len(allIDPs) == 0 {
		return errgo.Newf("no interactive login methods found")
	}
	if len(idps) == 0 {
		idps = allIDPs
	}
	if req.Header.Get("Accept") == "application/json" {
		httprequest.WriteJSON(w, http.StatusOK, params.IDPChoice{IDPs: idps})
		return nil
	}
	type authenticationRequiredParams struct {
		params.TemplateBrandParameters
		IDPs          []params.IDPChoiceDetails
		Error         string
		UseEmail      bool
		ShowEmailLink bool
		WithEmailURL  string
	}
	authParams := authenticationRequiredParams{
		TemplateBrandParameters: params.BrandParameters(),
		IDPs:                    idps,
		Error:                   errorMessage,
		UseEmail:                useEmail,
		ShowEmailLink:           h.params.EnableEmailLogin && domain == "" && !useEmail,
		WithEmailURL:            h.params.Location + "/login-email?state=" + state,
	}
	if err := h.params.Template.ExecuteTemplate(w, "authentication-required", authParams); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

type emailLoginRequest struct {
	httprequest.Route `httprequest:"GET /login-email"`

	// State holds the state information generated in the /login-redirect
	// handler.
	State string `httprequest:"state,form"`
}

// EmailLogin starts a request to choose an identity provider using an
// email address.
func (h *handler) EmailLogin(p httprequest.Params, req *emailLoginRequest) error {
	return h.authChoice(p.Response, p.Request, req.State, "", "", true)
}

type emailLoginSubmitRequest struct {
	httprequest.Route `httprequest:"POST /login-email"`

	// State holds the state information generated in the /login-redirect
	// handler.
	State string `httprequest:"state,form"`

	// Email holds the email address to use to select the identity
	// provider.
	Email string `httprequest:"email,form"`
}

// EmailLoginSubmit attemtps to find an identity provider suitable for
// use with the provided email address and either redirects to that
// identity provider, or outputs the same email form with an error message.
func (h *handler) EmailLoginSubmit(p httprequest.Params, req *emailLoginSubmitRequest) error {
	for _, idp := range h.params.IdentityProviders {
		type isForEmailAddrer interface {
			IsForEmailAddr(string) bool
		}
		matcher, ok := idp.(isForEmailAddrer)
		if !ok {
			continue
		}
		if matcher.IsForEmailAddr(req.Email) {
			http.Redirect(p.Response, p.Request, idp.URL(req.State), http.StatusSeeOther)
			return nil
		}
	}
	return h.authChoice(p.Response, p.Request, req.State, "", fmt.Sprintf(`cannot find identity provider for email address "%s"`, req.Email), true)
}

// loginCompleteRequest is a request that completes a login attempt.
type loginCompleteRequest struct {
	httprequest.Route `httprequest:"GET /login-complete"`

	// State holds the login state that was sent with the original
	// login request. This must match the candid-discharge-wait
	// cookie for the request to be processed.
	State string `httprequest:"state,form"`

	// Code holds the authorisation code to swap for the discharge
	// token. This is only set on successful requests.
	Code string `httprequest:"code,form"`

	// ErrorCode contains the error code, if any, for a failed login.
	ErrorCode string `httprequest:"error_code,form"`

	// Error holds the error message from a failed login.
	Error string `httprequest:"error,form"`
}

// LoginComplete handles completing the login process for visitor based
// login flows. The redirect based login will return here with either a
// code to get a discharge token, or an error. This endpoint completes
// any waiting endpoint.
func (h *handler) LoginComplete(p httprequest.Params, req *loginCompleteRequest) {
	ctx := p.Context
	var ws waitState
	if err := h.params.codec.Cookie(p.Request, waitCookieName, req.State, &ws); err != nil {
		logger.Infof("login error: %s", err)
		idputil.BadRequestf(p.Response, "invalid login state")
		return
	}

	if req.Error != "" {
		err := &params.Error{
			Message: req.Error,
			Code:    params.ErrorCode(req.ErrorCode),
		}
		h.params.visitCompleter.Failure(ctx, p.Response, p.Request, ws.DischargeID, err)
		return
	}

	var id store.Identity
	if err := h.params.identityStore.Get(ctx, req.Code, &id); err != nil {
		h.params.visitCompleter.Failure(ctx, p.Response, p.Request, ws.DischargeID, err)
		return
	}

	h.params.visitCompleter.Success(ctx, p.Response, p.Request, ws.DischargeID, &id)
}

const waitCookieName = "candid-discharge-wait"

// A waitState is a cookie that stores the current state of a login that
// is part of a interact/wait pair.
type waitState struct {
	DischargeID string
}
