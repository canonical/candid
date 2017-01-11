// Copyright 2015 Canonical Ltd.

// Package agent is an identity provider that uses the agent authentication scheme.
package agent

import (
	"net/http"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/juju/loggo"
	"github.com/juju/utils"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/store"
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

func init() {
	config.RegisterIDP("agent", func(func(interface{}) error) (idp.IdentityProvider, error) {
		return IdentityProvider, nil
	})
}

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

const agentLoginMacaroonDuration = 10 * time.Second

// Handle handles the agent login process.
func (a *identityProvider) Handle(c idp.Context) {
	p := c.Params()
	logger.Infof("agent handle %v", p.Request.URL)
	ctx := p.Context
	ac, ok := c.(agentContext)
	if !ok {
		c.LoginFailure(errgo.Newf("unsupported context"))
	}
	var login params.AgentLogin
	if al := ac.AgentLogin(); al.Username != "" {
		// Login shortcut - we're being asked directly to log in from
		// the /login endpoint - this isn't actually a callback to /agent
		// so we can't expect to find the curret login parameters there.
		login = al
	} else {
		var req agentLoginRequest
		if err := httprequest.Unmarshal(p, &req); err != nil {
			ac.LoginFailure(errgo.NoteMask(err, "cannot unmarshal request", errgo.Any))
			return
		}
		login = req.AgentLogin
	}
	loginOp := bakery.Op{
		Entity: "agent-" + string(login.Username),
		Action: "login",
	}
	ctx = httpbakery.ContextWithRequest(ctx, p.Request)
	ctx = store.ContextWithStore(ctx, ac.Store())
	_, err := c.Bakery().Checker.Auth(httpbakery.RequestMacaroons(p.Request)...).Allow(ctx, loginOp)
	if err == nil {
		if ac.LoginSuccess(login.Username, time.Now().Add(agentMacaroonDuration)) {
			httprequest.WriteJSON(p.Response, http.StatusOK,
				params.AgentLoginResponse{
					AgentLogin: true,
				},
			)
		}
		return
	}
	// TODO fail harder if the error isn't because of a verification error?

	// Verification has failed. The bakery checker will want us to
	// discharge a macaroon to prove identity, but we're already
	// part of the discharge process so we can't do that here.
	// Instead, mint a very short term macaroon containing
	// the local third party caveat that will allow access if discharged.

	vers := httpbakery.RequestVersion(c.Params().Request)
	m, err := ac.Bakery().Oven.NewMacaroon(
		ctx,
		vers,
		time.Now().Add(agentLoginMacaroonDuration),
		[]checkers.Caveat{
			bakery.LocalThirdPartyCaveat(login.PublicKey, vers),
			store.UserHasPublicKeyCaveat(login.Username, login.PublicKey),
		},
		loginOp,
	)
	if err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot create macaroon"))
		return
	}
	path, err := utils.RelativeURLPath(p.Request.URL.Path, "/")
	if err != nil {
		c.LoginFailure(errgo.Mask(err))
		return
	}

	err = httpbakery.NewDischargeRequiredErrorForRequest(m, path, nil, p.Request)
	err.(*httpbakery.Error).Info.CookieNameSuffix = "agent-login"
	identity.WriteError(ctx, p.Response, err)
}
