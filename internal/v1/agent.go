// Copyright 2015 Canonical Ltd.

package v1

import (
	"net/http"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/juju/utils"
	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent"

	"github.com/CanonicalLtd/blues-identity/internal/auth"
)

const (
	// agentMacaroonDuration is the length of time for which an agent
	// identity macaroon is valid. This is shorter than for users as
	// an agent can authenticate without interaction.
	agentMacaroonDuration = 30 * time.Minute

	// agentLoginMacaroonDuration is the lifetime of the intermediate
	// macaroon used in the agent login process.
	agentLoginMacaroonDuration = 10 * time.Second
)

// agentLoginCookieRequest is the expected request to the agent-login
// endpoint, when specifying the agent as a cookie.
type agentLoginCookieRequest struct {
	httprequest.Route `httprequest:"GET /v1/agent-login"`
	WaitID            string `httprequest:"waitid,form"`
}

// AgentLoginCookie is the endpoint used when performing an agent login
// using the agent-login cookie protocol.
func (h *dischargeHandler) AgentLoginCookie(p httprequest.Params, alr *agentLoginCookieRequest) (*params.AgentLoginResponse, error) {
	user, key, err := agent.LoginCookie(p.Request)
	if err != nil {
		if errgo.Cause(err) == agent.ErrNoAgentLoginCookie {
			return nil, errgo.WithCausef(err, params.ErrBadRequest, "")
		}
		return nil, errgo.Mask(err)
	}
	resp, err := h.agentLogin(p.Context, p.Request, alr.WaitID, params.Username(user), key)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return resp, nil

}

// agentLoginPostRequest is the expected request to the agent-login
// endpoint when using the POST protocol.
type agentLoginPostRequest struct {
	httprequest.Route `httprequest:"POST /v1/agent-login"`
	WaitID            string            `httprequest:"waitid,form"`
	AgentLogin        params.AgentLogin `httprequest:",body"`
}

// AgentLoginPost is the endpoint used when performing an agent login
// using the POST protocol.
func (h *dischargeHandler) AgentLoginPost(p httprequest.Params, alr *agentLoginPostRequest) (*params.AgentLoginResponse, error) {
	resp, err := h.agentLogin(p.Context, p.Request, alr.WaitID, alr.AgentLogin.Username, alr.AgentLogin.PublicKey)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return resp, nil
}

// agentLogin handles the common parts of the agent login protocols.
func (h *dischargeHandler) agentLogin(ctx context.Context, req *http.Request, waitID string, user params.Username, key *bakery.PublicKey) (*params.AgentLoginResponse, error) {
	loginOp := bakery.Op{
		Entity: "agent-" + string(user),
		Action: "login",
	}
	vers := httpbakery.RequestVersion(req)
	ctx = httpbakery.ContextWithRequest(ctx, req)
	ctx = auth.ContextWithStore(ctx, h.store)
	_, err := h.h.auth.Auth(ctx, httpbakery.RequestMacaroons(req), loginOp)
	if err == nil {
		if err := h.completeLogin(ctx, waitID, vers, user, time.Now().Add(agentMacaroonDuration)); err != nil {
			return nil, errgo.Mask(err)
		}
		return &params.AgentLoginResponse{
			AgentLogin: true,
		}, nil
	}
	// TODO fail harder if the error isn't because of a verification error?

	// Verification has failed. The bakery checker will want us to
	// discharge a macaroon to prove identity, but we're already
	// part of the discharge process so we can't do that here.
	// Instead, mint a very short term macaroon containing
	// the local third party caveat that will allow access if discharged.
	m, err := h.agentMacaroon(ctx, vers, loginOp, user, key)
	if err != nil {
		return nil, errgo.Notef(err, "cannot create macaroon")
	}
	path, err := utils.RelativeURLPath(req.URL.Path, "/")
	if err != nil {
		return nil, errgo.Mask(err)
	}
	err = httpbakery.NewDischargeRequiredErrorForRequest(m, path, nil, req)
	err.(*httpbakery.Error).Info.CookieNameSuffix = "agent-login"
	return nil, err
}

// agentMacaroon creates a new macaroon containing a local third-party
// caveat addressed to the specified agent.
func (h *dischargeHandler) agentMacaroon(ctx context.Context, vers bakery.Version, op bakery.Op, user params.Username, key *bakery.PublicKey) (*bakery.Macaroon, error) {
	m, err := h.h.oven.NewMacaroon(
		ctx,
		vers,
		time.Now().Add(agentLoginMacaroonDuration),
		[]checkers.Caveat{
			bakery.LocalThirdPartyCaveat(key, vers),
			auth.UserHasPublicKeyCaveat(user, key),
		},
		op,
	)
	return m, errgo.Mask(err)
}

// agentURL generates an approptiate URL for use with agent login
// protocols.
func (h *dischargeHandler) agentURL(waitID string) string {
	url := h.serviceURL("/v1/agent-login")
	if waitID != "" {
		url += "?waitid=" + waitID
	}
	return url
}
