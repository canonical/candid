// Copyright 2015 Canonical Ltd.

// Package agent is an identity provider that uses the agent authentication scheme.
package agent

import (
	"net/http"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/params"
)

// IdentityProvider is the instance of the agent identity provider.
var IdentityProvider idp.IdentityProvider = (*identityProvider)(nil)

var logger = loggo.GetLogger("identity.idp.agent")

const (
	// agentMacaroonDuration is the length of time for which an agent
	// identity macaroon is valid. This is shorter than for users as
	// an agent can authenticate without interaction.
	agentMacaroonDuration = 30 * time.Minute
)

// identityProvider allows login using pre-registered agent users.
type identityProvider struct{}

// Name gives the name of the identity provider (agent).
func (*identityProvider) Name() string {
	return "agent"
}

// Description gives a description of the identity provider.
func (*identityProvider) Description() string {
	return "Agent"
}

// Interactive specifies that this identity provider is not interactive.
func (*identityProvider) Interactive() bool {
	return false
}

// URL gets the login URL to use this identity provider.
func (*identityProvider) URL(c idp.URLContext, waitID string) (string, error) {
	callback := c.URL("/agent")
	if waitID != "" {
		callback += "?waitid=" + waitID
	}
	return callback, nil
}

// agentLoginRequest is the expected request to the login endpoint.
type agentLoginRequest struct {
	params.AgentLogin `httprequest:",body"`
}

// agentContext provides an interface to the agent identity provider to
// access some internal idp context.
//
// TODO (mhilton) remove the need for special access.
type agentContext interface {
	idp.Context
	AgentLogin() params.AgentLogin
	Store() *store.Store
}

// Handle handles the agent login process.
func (a *identityProvider) Handle(c idp.Context) {
	ac, ok := c.(agentContext)
	if !ok {
		c.LoginFailure(errgo.Newf("unsupported context"))
	}
	p := ac.Params()
	var login agentLoginRequest
	if ac.AgentLogin().Username != "" {
		login.AgentLogin = ac.AgentLogin()
	} else {
		if err := httprequest.Unmarshal(p, &login); err != nil {
			ac.LoginFailure(errgo.NoteMask(err, "cannot unmarshal request", errgo.Any))
			return
		}
	}
	for _, ms := range httpbakery.RequestMacaroons(p.Request) {
		declared := checkers.InferDeclared(ms)
		err := c.Bakery().Check(ms, checkers.New(
			store.UserHasPublicKeyChecker{Store: ac.Store()},
			checkers.TimeBefore,
			httpbakery.Checkers(p.Request),
			declared,
			checkers.OperationChecker("discharge"),
		))
		if err == nil {
			if ac.LoginSuccess(ms) {
				httprequest.WriteJSON(p.Response, http.StatusOK,
					params.AgentLoginResponse{
						AgentLogin: true,
					},
				)
			}
			return
		}
		if _, ok := errgo.Cause(err).(*bakery.VerificationError); !ok {
			ac.LoginFailure(err)
			return
		}
		logger.Infof("verification error: %s", err)
	}
	m, err := ac.Bakery().NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", string(login.Username)),
		bakery.LocalThirdPartyCaveat(login.PublicKey),
		store.UserHasPublicKeyCaveat(login.Username, login.PublicKey),
		checkers.TimeBeforeCaveat(time.Now().Add(agentMacaroonDuration)),
	})
	if err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot create macaroon"))
		return
	}
	path, err := store.RelativeURLPath(p.Request.URL.Path, "/")
	if err != nil {
		c.LoginFailure(errgo.Mask(err))
		return
	}
	httpbakery.WriteDischargeRequiredError(p.Response, m, path, nil)
}
