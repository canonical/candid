// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"net/http"

	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/blues-identity/idp"
)

// legacyLoginRequest is a request to start a login to the identity manager
// using the legacy visit-wait protocol.
type legacyLoginRequest struct {
	httprequest.Route `httprequest:"GET /login-legacy"`
	Domain            string `httprequest:"domain,form"`
	DischargeID       string `httprequest:"did,form"`
}

// LoginLegacy handles the GET /v1/login-legacy endpoint that is used to log in to IdM
// when the legacy visit-wait protocol is used.
func (h *handler) LoginLegacy(p httprequest.Params, lr *legacyLoginRequest) error {
	// We should really be parsing the accept header properly here, but
	// it's really complicated http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.1
	// perhaps use http://godoc.org/bitbucket.org/ww/goautoneg for this.
	// Probably not worth it now that it's only part of the legacy protocol.
	if p.Request.Header.Get("Accept") == "application/json" {
		methods := map[string]string{"agent": h.agentURL(lr.DischargeID)}
		for _, idp := range h.params.IdentityProviders {
			methods[idp.Name()] = idp.URL(lr.DischargeID)
		}
		err := httprequest.WriteJSON(p.Response, http.StatusOK, methods)
		if err != nil {
			return errgo.Notef(err, "cannot write login methods")
		}
		return nil
	}

	_, _, err := agent.LoginCookie(p.Request)
	if errgo.Cause(err) != agent.ErrNoAgentLoginCookie {
		resp, err := h.AgentLogin(p, &agentLoginRequest{
			DischargeID: lr.DischargeID,
		})
		if err != nil {
			return errgo.Mask(err, errgo.Any)
		}
		return httprequest.WriteJSON(p.Response, http.StatusOK, resp)
	}
	if err != nil && errgo.Cause(err) != agent.ErrNoAgentLoginCookie {
		return errgo.Notef(err, "bad agent-login cookie")
	}
	return h.login(p, lr.DischargeID, lr.Domain)
}

// loginRequest is a request to start a login to the identity manager.
type loginRequest struct {
	httprequest.Route `httprequest:"GET /login"`
	Domain            string `httprequest:"domain,form"`
	DischargeID       string `httprequest:"did,form"`
}

// Login handles the GET /v1/login endpoint that is used to log in to IdM
// when an interactive visit-wait protocol has been chosen by the client.
func (h *handler) Login(p httprequest.Params, lr *loginRequest) error {
	return h.login(p, lr.DischargeID, lr.Domain)
}

// login handles a visit request for the given discharge ID and client-specified
// domain. It chooses the first applicable interactive identity provider that
// matches the client-specified domain, or the first interactive identity provider
// if none do.
func (h *handler) login(p httprequest.Params, dischargeID, domain string) error {
	// Use the normal interactive login method.
	var selected idp.IdentityProvider
	for _, idp := range h.params.IdentityProviders {
		if !idp.Interactive() {
			continue
		}
		// Select the first interactive identity provider even if
		// it does not match the domain. If no subsequent match
		// is found for the domain then this identity provider
		// will be used.
		if selected == nil {
			selected = idp
		}
		if domain == "" {
			break
		}
		if idp.Domain() == domain {
			selected = idp
			break
		}
	}
	if selected == nil {
		return errgo.Newf("no interactive login methods found")
	}
	url := selected.URL(dischargeID)
	http.Redirect(p.Response, p.Request, url, http.StatusFound)
	return nil
}
