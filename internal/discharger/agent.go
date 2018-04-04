// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"net/http"
	"time"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/juju/idmclient.v1"
	"gopkg.in/juju/idmclient.v1/params"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/blues-identity/internal/auth"
	"github.com/CanonicalLtd/blues-identity/store"
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

// agentLoginRequest is the expected GET request to the agent-login
// endpoint.
type agentLoginRequest struct {
	httprequest.Route `httprequest:"GET /login/agent"`
	Version           int    `httprequest:"v,form"`
	DischargeID       string `httprequest:"did,form"`
}

type agentMacaroonResponse struct {
	Macaroon *bakery.Macaroon `json:"macaroon"`
}

// AgentLogin is the endpoint used when performing an agent login
// using the agent-login cookie based protocols.
func (h *handler) AgentLogin(p httprequest.Params, req *agentLoginRequest) (interface{}, error) {
	switch req.Version {
	default:
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "unsupported protocol version %d", req.Version)
	case 1:
		return h.agentLoginV1(p.Context, req.DischargeID, p.Request)
	case 0:
	}
	user, key, err := agent.LoginCookie(p.Request)
	if err != nil {
		if errgo.Cause(err) == agent.ErrNoAgentLoginCookie {
			return nil, errgo.WithCausef(err, params.ErrBadRequest, "")
		}
		return nil, errgo.Mask(err)
	}
	resp, err := h.agentLogin(p.Context, p.Request, req.DischargeID, user, key)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return resp, nil
}

func (h *handler) agentLoginV1(ctx context.Context, dischargeID string, req *http.Request) (*agentMacaroonResponse, error) {
	username := req.Form.Get("username")
	if username == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "username not specified")
	}
	pk := req.Form.Get("public-key")
	if pk == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "public-key not specified")
	}
	var key bakery.PublicKey
	if err := key.Key.UnmarshalText([]byte(pk)); err != nil {
		return nil, errgo.WithCausef(err, params.ErrBadRequest, "invalid public-key")
	}
	m, err := h.agentMacaroon(ctx, httpbakery.RequestVersion(req), identchecker.LoginOp, username, &key, dischargeID)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &agentMacaroonResponse{Macaroon: m}, nil
}

// agentLoginPostRequest is the expected request to the agent-login
// endpoint when using the POST protocol.
type agentLoginPostRequest struct {
	httprequest.Route `httprequest:"POST /login/agent"`
	DischargeID       string            `httprequest:"did,form"`
	AgentLogin        params.AgentLogin `httprequest:",body"`
}

// AgentLoginPost is the endpoint used when performing an agent login
// using the POST protocol.
func (h *handler) AgentLoginPost(p httprequest.Params, alr *agentLoginPostRequest) (*agent.LegacyAgentResponse, error) {
	resp, err := h.agentLogin(p.Context, p.Request, alr.DischargeID, string(alr.AgentLogin.Username), alr.AgentLogin.PublicKey)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return resp, nil
}

// agentLogin handles the common parts of the agent login protocols.
func (h *handler) agentLogin(ctx context.Context, req *http.Request, dischargeID string, user string, key *bakery.PublicKey) (*agent.LegacyAgentResponse, error) {
	loginOp := loginOp(user)
	vers := httpbakery.RequestVersion(req)
	ctx = httpbakery.ContextWithRequest(ctx, req)
	ctx = auth.ContextWithDischargeID(ctx, dischargeID)
	_, err := h.params.Authorizer.Auth(ctx, httpbakery.RequestMacaroons(req), loginOp)
	if err == nil {
		dt, err := h.params.dischargeTokenCreator.DischargeToken(ctx, dischargeID, &store.Identity{
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
	m, err := h.agentMacaroon(ctx, vers, loginOp, user, key, dischargeID)
	if err != nil {
		return nil, errgo.Notef(err, "cannot create macaroon")
	}
	return nil, httpbakery.NewDischargeRequiredError(httpbakery.DischargeRequiredErrorParams{
		Macaroon:         m,
		Request:          req,
		CookieNameSuffix: "agent-login",
	})
}

// agentMacaroon creates a new macaroon containing a local third-party
// caveat addressed to the specified agent.
func (h *handler) agentMacaroon(ctx context.Context, vers bakery.Version, op bakery.Op, user string, key *bakery.PublicKey, dischargeID string) (*bakery.Macaroon, error) {
	m, err := h.params.Oven.NewMacaroon(
		ctx,
		vers,
		[]checkers.Caveat{
			checkers.TimeBeforeCaveat(time.Now().Add(agentLoginMacaroonDuration)),
			idmclient.UserDeclaration(user),
			bakery.LocalThirdPartyCaveat(key, vers),
			auth.UserHasPublicKeyCaveat(params.Username(user), key),
			auth.DischargeIDCaveat(dischargeID),
		},
		op,
	)
	return m, errgo.Mask(err)
}

// agentURL generates an approptiate URL for use with agent login
// protocols.
func (h *handler) agentURL(dischargeID string) string {
	url := h.params.Location + "/login/agent"
	if dischargeID != "" {
		url += "?did=" + dischargeID
	}
	return url
}

func loginOp(user string) bakery.Op {
	return bakery.Op{
		Entity: "agent-" + user,
		Action: "login",
	}
}
