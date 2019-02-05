// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package agent is an identity provider that uses the agent authentication scheme.
package agent

import (
	"context"
	"net/http"

	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/store"
)

// IdentityProvider is the instance of the agent identity provider.
//
// Note: this identity provider will no longer be used, it is provided
// for backwards-compatibility purposes only. The agent functionality is
// now built in to the identity manager.
var IdentityProvider idp.IdentityProvider = (*identityProvider)(nil)

func init() {
	idp.Register("agent", func(func(interface{}) error) (idp.IdentityProvider, error) {
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

// Init implements idp.IdentityProvider.Init by doing nothing.
func (*identityProvider) Init(context.Context, idp.InitParams) error {
	return errgo.New("agent login IDP no longer supported")
}

// URL gets the login URL to use this identity provider.
func (*identityProvider) URL(string) string {
	return ""
}

// SetInteraction implements idp.IdentityProvider.SetInteraction by doing
// nothing.
func (*identityProvider) SetInteraction(ierr *httpbakery.Error, dischargeID string) {
}

// Handle handles the agent login process.
func (*identityProvider) Handle(context.Context, http.ResponseWriter, *http.Request) {
}

//  GetGroups implements idp.IdentityProvider.GetGroups.
func (*identityProvider) GetGroups(context.Context, *store.Identity) ([]string, error) {
	return nil, nil
}
