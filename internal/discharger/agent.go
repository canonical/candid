// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"net/http"
	"time"

	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/candid/internal/auth"
	"github.com/CanonicalLtd/candid/store"
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

func loginOp(user string) bakery.Op {
	return bakery.Op{
		Entity: "agent-" + user,
		Action: "login",
	}
}

// agentLoginRequest is the expected GET request to the agent-login
// endpoint. Note: this is compatible with the parameters used for the
// agent login request in the httpbakery/agent package.
type agentLoginRequest struct {
	httprequest.Route `httprequest:"GET /login/agent"`
	DischargeID       string            `httprequest:"did,form"`
	Username          string            `httprequest:"username,form"`
	PublicKey         *bakery.PublicKey `httprequest:"public-key,form"`
}

type agentMacaroonResponse struct {
	Macaroon *bakery.Macaroon `json:"macaroon"`
}

// agentURL returns the URL path for the agent-login endpoint for the
// candid service at the given location.
func agentURL(location string, dischargeID string) string {
	p := location + "/login/agent"
	if dischargeID != "" {
		p += "?did=" + dischargeID
	}
	return p
}

// AgentLogin is the endpoint used to acquire an agent macaroon
// as part of a discharge request.
func (h *handler) AgentLogin(p httprequest.Params, req *agentLoginRequest) (*agentMacaroonResponse, error) {
	if req.Username == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "username not specified")
	}
	if req.PublicKey == nil {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "public-key not specified")
	}
	m, err := h.agentMacaroon(p.Context, httpbakery.RequestVersion(p.Request), identchecker.LoginOp, req.Username, req.PublicKey)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &agentMacaroonResponse{Macaroon: m}, nil
}

// agentMacaroon creates a new macaroon containing a local third-party
// caveat addressed to the specified agent.
func (h *handler) agentMacaroon(ctx context.Context, vers bakery.Version, op bakery.Op, user string, key *bakery.PublicKey) (*bakery.Macaroon, error) {
	m, err := h.params.Oven.NewMacaroon(
		ctx,
		vers,
		[]checkers.Caveat{
			checkers.TimeBeforeCaveat(time.Now().Add(agentLoginMacaroonDuration)),
			candidclient.UserDeclaration(user),
			bakery.LocalThirdPartyCaveat(key, vers),
			auth.UserHasPublicKeyCaveat(params.Username(user), key),
		},
		op,
	)
	return m, errgo.Mask(err)
}

// legacyAgentLoginRequest is the expected GET request to the agent-login
// endpoint.
type legacyAgentLoginRequest struct {
	httprequest.Route `httprequest:"GET /login/legacy-agent"`
	DischargeID       string `httprequest:"did,form"`
}

// LegacyAgentLogin is the endpoint used when performing agent login
// using the legacy agent-login cookie based protocols.
func (h *handler) LegacyAgentLogin(p httprequest.Params, req *legacyAgentLoginRequest) (interface{}, error) {
	user, key, err := agent.LoginCookie(p.Request)
	if err != nil {
		if errgo.Cause(err) == agent.ErrNoAgentLoginCookie {
			return nil, errgo.WithCausef(err, params.ErrBadRequest, "")
		}
		return nil, errgo.Mask(err)
	}
	resp, err := h.legacyAgentLogin(p.Context, p.Request, req.DischargeID, user, key)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return resp, nil
}

// legacyAgentLoginPostRequest is the expected request to the agent-login
// endpoint when using the POST protocol.
type legacyAgentLoginPostRequest struct {
	httprequest.Route `httprequest:"POST /login/legacy-agent"`
	DischargeID       string            `httprequest:"did,form"`
	AgentLogin        params.AgentLogin `httprequest:",body"`
}

// LegacyAgentLoginPost is the endpoint used when performing an agent login
// using the POST protocol.
func (h *handler) LegacyAgentLoginPost(p httprequest.Params, req *legacyAgentLoginPostRequest) (*agent.LegacyAgentResponse, error) {
	resp, err := h.legacyAgentLogin(p.Context, p.Request, req.DischargeID, string(req.AgentLogin.Username), req.AgentLogin.PublicKey)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return resp, nil
}

// legacyAgentLogin handles the common parts of the legacy agent login protocols.
func (h *handler) legacyAgentLogin(ctx context.Context, req *http.Request, dischargeID string, user string, key *bakery.PublicKey) (*agent.LegacyAgentResponse, error) {
	loginOp := loginOp(user)
	vers := httpbakery.RequestVersion(req)
	ctx = httpbakery.ContextWithRequest(ctx, req)
	ctx = auth.ContextWithDischargeID(ctx, dischargeID)
	_, err := h.params.Authorizer.Auth(ctx, httpbakery.RequestMacaroons(req), loginOp)
	if err == nil {
		dt, err := h.params.dischargeTokenCreator.DischargeToken(ctx, &store.Identity{
			Username: user,
		})
		if err != nil {
			return nil, errgo.Mask(err)
		}
		h.params.place.Done(ctx, dischargeID, &loginInfo{
			DischargeToken: dt,
		})
		return &agent.LegacyAgentResponse{
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
	return nil, httpbakery.NewDischargeRequiredError(httpbakery.DischargeRequiredErrorParams{
		Macaroon:         m,
		Request:          req,
		CookieNameSuffix: "agent-login",
	})
}

// legacyAgentURL returns the URL path for the legacy agent login endpoint
// for the candid service at the given location.
func legacyAgentURL(location string, dischargeID string) string {
	p := location + "/login/legacy-agent"
	if dischargeID != "" {
		p += "?did=" + dischargeID
	}
	return p
}
