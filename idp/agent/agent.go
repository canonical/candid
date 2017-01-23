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
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
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

// Domain returns "" as the agent identity provider will not create
// users.
func (*identityProvider) Domain() string {
	return ""
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
func (*identityProvider) URL(ctx idp.Context, waitID string) string {
	return idputil.URL(ctx, "/agent", waitID)
}

// Init implements idp.IdentityProvider.Init by doing nothing.
func (*identityProvider) Init(idp.Context) error {
	return nil
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
	idp.RequestContext
	AgentLogin() params.AgentLogin
	Store() *store.Store
}

const agentLoginMacaroonDuration = 10 * time.Second

// Handle handles the agent login process.
func (a *identityProvider) Handle(rctx idp.RequestContext, w http.ResponseWriter, req *http.Request) {
	logger.Infof("agent handle %v", req.URL)
	ac, ok := rctx.(agentContext)
	if !ok {
		rctx.LoginFailure(idputil.WaitID(req), errgo.Newf("unsupported context"))
	}
	var login params.AgentLogin
	if al := ac.AgentLogin(); al.Username != "" {
		// Login shortcut - we're being asked directly to log in from
		// the /login endpoint - this isn't actually a callback to /agent
		// so we can't expect to find the curret login parameters there.
		login = al
	} else {
		var alr agentLoginRequest
		if err := httprequest.Unmarshal(idputil.RequestParams(rctx, w, req), &alr); err != nil {
			ac.LoginFailure(idputil.WaitID(req), errgo.NoteMask(err, "cannot unmarshal request", errgo.Any))
			return
		}
		login = alr.AgentLogin
	}
	loginOp := bakery.Op{
		Entity: "agent-" + string(login.Username),
		Action: "login",
	}
	ctx := httpbakery.ContextWithRequest(rctx, req)
	ctx = store.ContextWithStore(ctx, ac.Store())
	_, err := ac.Bakery().Checker.Auth(httpbakery.RequestMacaroons(req)...).Allow(ctx, loginOp)
	if err == nil {
		if ac.LoginSuccess(idputil.WaitID(req), login.Username, time.Now().Add(agentMacaroonDuration)) {
			httprequest.WriteJSON(w, http.StatusOK,
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

	vers := httpbakery.RequestVersion(req)
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
		ac.LoginFailure(idputil.WaitID(req), errgo.Notef(err, "cannot create macaroon"))
		return
	}
	path, err := utils.RelativeURLPath(req.URL.Path, "/")
	if err != nil {
		ac.LoginFailure(idputil.WaitID(req), errgo.Mask(err))
		return
	}

	err = httpbakery.NewDischargeRequiredErrorForRequest(m, path, nil, req)
	err.(*httpbakery.Error).Info.CookieNameSuffix = "agent-login"
	identity.WriteError(ctx, w, err)
}
