// Copyright 2015 Canonical Ltd.

package v1

import (
	"fmt"
	"net/http"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/httpbakery/agent"

	"github.com/CanonicalLtd/blues-identity/params"
)

// loginRequest is a request to start a login to the identity manager.
type loginRequest struct {
	httprequest.Route `httprequest:"GET /v1/login"`
	WaitID            string `httprequest:"waitid,form"`
}

// login handles the GET /v1/login endpoint that is used to log in to IdM.
func (h *dischargeHandler) Login(p httprequest.Params, lr *loginRequest) error {
	user, key, err := agent.LoginCookie(p.Request)
	if err == nil && h.agentLogin(user, key) {
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
				h:     h.h,
				store: h.store,
				idp:   idp,
			}
			var err error
			methods[idp.Name()], err = idp.URL(ctxt, lr.WaitID)
			if err != nil {
				return errgo.NoteMask(err, fmt.Sprintf("cannot get URL for %q", idp.Name()), errgo.Any)
			}
		}
		err := httprequest.WriteJSON(p.Response, http.StatusOK, methods)
		if err != nil {
			return errgo.Notef(err, "cannot write login methods")
		}
		return nil
	}
	// Use the normal interactive login method.
	for _, idp := range h.h.idps {
		if idp.Interactive() {
			ctxt := &idpHandler{
				h:     h.h,
				store: h.store,
				idp:   idp,
			}
			url, err := idp.URL(ctxt, lr.WaitID)
			if err != nil {
				return errgo.NoteMask(err, fmt.Sprintf("cannot get URL for %q", idp.Name()), errgo.Any)
			}
			http.Redirect(p.Response, p.Request, url, http.StatusFound)
			return nil
		}
	}
	return errgo.Newf("no interactive login methods found")
}

// agentLogin provides a shortcut to log in to the agent identity
// provider if an appropriate cookie has been provided in the login
// request. The return value indicates if an agent identity provider was
// found and therefore the login attempted.
func (h *dischargeHandler) agentLogin(user string, key *bakery.PublicKey) bool {
	for _, idp := range h.h.idps {
		if idp.Name() != "agent" {
			continue
		}
		ctxt := &idpHandler{
			h:      h.h,
			store:  h.store,
			idp:    idp,
			place:  h.place,
			params: h.params,
			agentLogin: params.AgentLogin{
				Username:  params.Username(user),
				PublicKey: key,
			},
		}
		idp.Handle(ctxt)
		return true
	}
	logger.Warningf("agent cookie found, but agent identity provider not configured")
	return false
}
