// Copyright 2015 Canonical Ltd.

package v1

import (
	"net/http"
	"net/url"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"

	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/params"
)

func (h *dischargeHandler) agentLoginURL(waitid string) string {
	url := h.serviceURL("/v1/agent")
	if waitid != "" {
		url += "?waitid=" + waitid
	}
	return url
}

// agentLoginRequest is a request to perform an agent login. Agents
// claim an identity along with a public key associated with that
// identity. Any discharge macroons that are generated for an agent will
// contain a third party caveat addressed to "local" that they will have
// to discharge to prove that they hold the private key.
type agentLoginRequest struct {
	httprequest.Route `httprequest:"POST /v1/agent"`
	WaitID            string `httprequest:"waitid,form"`
	params.AgentLogin `httprequest:",body"`
}

// AgentLogin is used to attempt to log in using agent credentials.
func (h *dischargeHandler) AgentLogin(p httprequest.Params, login *agentLoginRequest) {
	for _, ms := range httpbakery.RequestMacaroons(p.Request) {
		declared := checkers.InferDeclared(ms)
		err := h.store.Service.Check(ms, checkers.New(
			identity.UserHasPublicKeyChecker{Store: h.store},
			checkers.TimeBefore,
			httpbakery.Checkers(p.Request),
			declared,
			checkers.OperationChecker("discharge"),
		))
		if err == nil {
			if h.loginSuccess(p.Response, p.Request, declared["username"], ms) {
				httprequest.WriteJSON(p.Response, http.StatusOK, login.AgentLogin)
			}
			return
		}
		if _, ok := errgo.Cause(err).(*bakery.VerificationError); !ok {
			h.loginFailure(p.Response, p.Request, declared["username"], err)
			return
		}
		logger.Infof("verification error: %s", err)
	}
	m, err := h.store.Service.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", string(login.Username)),
		bakery.LocalThirdPartyCaveat(login.PublicKey),
		identity.UserHasPublicKeyCaveat(login.Username, login.PublicKey),
	})
	if err != nil {
		h.loginFailure(p.Response, p.Request, string(login.Username), errgo.Notef(err, "cannot create macaroon"))
		return
	}
	u, err := url.Parse(h.h.location)
	if err != nil {
		h.loginFailure(p.Response, p.Request, string(login.Username), errgo.Notef(err, "cannot parse location"))
		return
	}
	httpbakery.WriteDischargeRequiredError(p.Response, m, u.Path, nil)
}
