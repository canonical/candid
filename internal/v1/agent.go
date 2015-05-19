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

	"github.com/CanonicalLtd/blues-identity/internal/server"
	"github.com/CanonicalLtd/blues-identity/params"
)

func (h *Handler) agentLoginURL(waitid string) string {
	url := h.location + "/v1/agent"
	if waitid != "" {
		url += "?waitid=" + waitid
	}
	return url
}

type agentLoginRequest struct {
	params.AgentLoginRequest `httprequest:",body"`
}

func (h *Handler) agentLogin(w http.ResponseWriter, p httprequest.Params, login *agentLoginRequest) {
	for _, ms := range httpbakery.RequestMacaroons(p.Request) {
		err := h.svc.Check(ms, checkers.New(
			server.UserHasPublicKeyChecker{Store: h.store},
			checkers.TimeBefore,
			httpbakery.Checkers(p.Request),
			checkers.InferDeclared(ms),
		))
		if err == nil {
			h.loginSuccess(w, p.Request, ms, "agent login complete")
			return
		}
		if _, ok := errgo.Cause(err).(*bakery.VerificationError); !ok {
			h.loginFailure(w, p.Request, err)
			return
		}
		logger.Infof("verification error: %s", err)
	}
	m, err := h.svc.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", string(login.Username)),
		bakery.LocalThirdPartyCaveat(login.PublicKey),
		server.UserHasPublicKeyCaveat(login.Username, login.PublicKey),
	})
	if err != nil {
		h.loginFailure(w, p.Request, errgo.Notef(err, "cannot create macaroon"))
		return
	}
	u, err := url.Parse(h.location)
	if err != nil {
		h.loginFailure(w, p.Request, errgo.Notef(err, "cannot parse location"))
		return
	}
	httpbakery.WriteDischargeRequiredError(w, m, u.Path, nil)
}
