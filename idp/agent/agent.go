// Copyright 2015 Canonical Ltd.

// Package agent is an identity provider that uses the agent authentication scheme.
package agent

import (
	"net/http"

	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
)

// IdentityProvider is the instance of the agent identity provider.
//
// Note: this identity provider will no longer be used, it is provided
// for backwards-compatibility purposes only. The agent functionality is
// now built in to the identity manager.
var IdentityProvider idp.IdentityProvider = (*identityProvider)(nil)

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
	return ""
}

// Interactive specifies that this identity provider is not interactive.
func (*identityProvider) Interactive() bool {
	return false
}

// URL gets the login URL to use this identity provider.
func (*identityProvider) URL(ctx idp.Context, waitID string) string {
	return ""
}

// Init implements idp.IdentityProvider.Init by doing nothing.
func (*identityProvider) Init(idp.Context) error {
	return errgo.New("agent login IDP no longer supported")
}

// Handle handles the agent login process.
func (a *identityProvider) Handle(rctx idp.RequestContext, w http.ResponseWriter, req *http.Request) {
}
