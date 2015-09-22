// Copyright 2015 Canonical Ltd.

package idp

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"

	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/params"
)

// AgentLoginer is an interface that might be used to pass agent login
// information that is sourced from somewhere other than the request body
// into the agent login process. It is used to pass agent login cookies
// from the login endpoint.
type AgentLoginer interface {
	AgentLogin() params.AgentLogin
}

// AgentIdentityProvider allows login using pre-registered agent users.
type AgentIdentityProvider struct {
	path string
}

// NewAgentIdentityProvider creates new AgentIdentityProvider. It
// requires the location of the IdM being created .
func NewAgentIdentityProvider(location string) (*AgentIdentityProvider, error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, errgo.Notef(err, "cannot parse location")
	}
	path := u.Path
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	return &AgentIdentityProvider{path}, nil
}

// Name gives the name of the identity provider (agent).
func (*AgentIdentityProvider) Name() string {
	return "agent"
}

// Description gives a description of the identity provider.
func (*AgentIdentityProvider) Description() string {
	return "Agent"
}

// Interactive specifies that this identity provider is not interactive.
func (*AgentIdentityProvider) Interactive() bool {
	return false
}

// URL gets the login URL to use this identity provider.
func (*AgentIdentityProvider) URL(c Context, waitID string) (string, error) {
	callback := c.IDPURL("/agent")
	if waitID != "" {
		callback += "?waitid=" + waitID
	}
	return callback, nil
}

// agentLoginRequest is the expected request to the login endpoint.
type agentLoginRequest struct {
	params.AgentLogin `httprequest:",body"`
}

// Handle handles the agent login process.
func (a *AgentIdentityProvider) Handle(c Context) {
	p := c.Params()
	var login agentLoginRequest
	if ac, ok := c.(AgentLoginer); ok && ac.AgentLogin().Username != "" {
		login.AgentLogin = ac.AgentLogin()
	} else {
		if err := httprequest.Unmarshal(p, &login); err != nil {
			c.LoginFailure(errgo.NoteMask(err, "cannot unmarshal request", errgo.Any))
			return
		}
	}
	for _, ms := range httpbakery.RequestMacaroons(p.Request) {
		declared := checkers.InferDeclared(ms)
		err := c.Store().Service.Check(ms, checkers.New(
			store.UserHasPublicKeyChecker{Store: c.Store()},
			checkers.TimeBefore,
			httpbakery.Checkers(p.Request),
			declared,
			checkers.OperationChecker("discharge"),
		))
		if err == nil {
			if c.LoginSuccess(ms) {
				httprequest.WriteJSON(p.Response, http.StatusOK,
					params.AgentLoginResponse{
						AgentLogin: true,
					},
				)
			}
			return
		}
		if _, ok := errgo.Cause(err).(*bakery.VerificationError); !ok {
			c.LoginFailure(err)
			return
		}
		logger.Infof("verification error: %s", err)
	}
	m, err := c.Store().Service.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", string(login.Username)),
		bakery.LocalThirdPartyCaveat(login.PublicKey),
		store.UserHasPublicKeyCaveat(login.Username, login.PublicKey),
	})
	if err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot create macaroon"))
		return
	}
	httpbakery.WriteDischargeRequiredError(p.Response, m, a.path, nil)
}
