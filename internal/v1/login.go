// Copyright 2015 Canonical Ltd.

package v1

import (
	"net/http"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent"
)

// loginRequest is a request to start a login to the identity manager.
type loginRequest struct {
	httprequest.Route `httprequest:"GET /v1/login"`
	Domain            string `httprequest:"domain,form"`
	WaitID            string `httprequest:"waitid,form"`
}

// login handles the GET /v1/login endpoint that is used to log in to IdM.
func (h *dischargeHandler) Login(p httprequest.Params, lr *loginRequest) error {
	user, key, err := agent.LoginCookie(p.Request)
	if err == nil && h.agentLogin(p, user, key) {
		return nil
	}
	if err != nil && errgo.Cause(err) != agent.ErrNoAgentLoginCookie {
		return errgo.Notef(err, "bad agent-login cookie")
	}
	// TODO should really be parsing the accept header properly here, but
	// it's really complicated http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.1
	// perhaps use http://godoc.org/bitbucket.org/ww/goautoneg for this.
	if p.Request.Header.Get("Accept") == "application/json" {
		methods := make(map[string]string)
		for _, idp := range h.h.idps {
			ctxt := &idpHandler{
				Context: p.Context,
				h:       h.h,
				store:   h.store,
				idp:     idp,
			}
			methods[idp.Name()] = idp.URL(ctxt, lr.WaitID)
		}
		err := httprequest.WriteJSON(p.Response, http.StatusOK, methods)
		if err != nil {
			return errgo.Notef(err, "cannot write login methods")
		}
		return nil
	}
	// Use the normal interactive login method.
	var selected idp.IdentityProvider
	for _, idp := range h.h.idps {
		if !idp.Interactive() {
			continue
		}
		// Select the first interactive identity provider even if
		// it does not match the domain.If no subsequent match is
		// found for the domain then this identity provider will
		// be used.
		if selected == nil {
			selected = idp
		}
		if lr.Domain == "" {
			break
		}
		if idp.Domain() == lr.Domain {
			selected = idp
			break
		}
	}
	if selected == nil {
		return errgo.Newf("no interactive login methods found")
	}
	ctxt := &idpHandler{
		Context: p.Context,
		h:       h.h,
		store:   h.store,
		idp:     selected,
	}
	url := selected.URL(ctxt, lr.WaitID)
	http.Redirect(p.Response, p.Request, url, http.StatusFound)
	return nil
}

// agentLogin provides a shortcut to log in to the agent identity
// provider if an appropriate cookie has been provided in the login
// request. The return value indicates if an agent identity provider was
// found and therefore the login attempted.
func (h *dischargeHandler) agentLogin(p httprequest.Params, user string, key *bakery.PublicKey) bool {
	for _, idp := range h.h.idps {
		if idp.Name() != "agent" {
			continue
		}
		ctxt := &idpHandler{
			Context:        p.Context,
			h:              h.h,
			store:          h.store,
			idp:            idp,
			place:          h.place,
			responseWriter: p.Response,
			request:        p.Request,
			agentLogin: params.AgentLogin{
				Username:  params.Username(user),
				PublicKey: key,
			},
		}
		idp.Handle(ctxt, p.Response, p.Request)
		return true
	}
	logger.Warningf("agent cookie found, but agent identity provider not configured")
	return false
}
