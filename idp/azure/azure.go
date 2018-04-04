// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package azure is an identity provider that authenticates with azure.
package azure

import (
	oidc "github.com/coreos/go-oidc"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/openid"
)

func init() {
	config.RegisterIDP("azure", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
		var p Params
		if err := unmarshal(&p); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal azure parameters")
		}
		if p.ClientID == "" {
			return nil, errgo.Newf("client-id not specified")
		}
		if p.ClientSecret == "" {
			return nil, errgo.Newf("client-secret not specified")
		}
		return NewIdentityProvider(p), nil
	})
}

type Params struct {
	// ClientID contains the Application Id for the application
	// registered at https://apps.dev.microsoft.com.
	ClientID string `yaml:"client-id"`

	// ClientSecret contains a password type Application Secret for
	// the application as generated on
	// https://apps.dev.microsoft.com.
	ClientSecret string `yaml:"client-secret"`
}

// NewIdentityProvider creates an azure identity provider with the
// configuration defined by p.
func NewIdentityProvider(p Params) idp.IdentityProvider {
	return openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Name:         "azure",
		Issuer:       "https://login.live.com",
		Domain:       "azure",
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
	})
}
