// Copyright 2017 Canonical Ltd.

// Package google is an identity provider that authenticates with google.
package google

import (
	"gopkg.in/errgo.v1"

	oidc "github.com/coreos/go-oidc"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/openid"
)

func init() {
	config.RegisterIDP("google", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
		var p Params
		if err := unmarshal(&p); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal google parameters")
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
	// registered at
	// https://console.developers.google.com/apis/credentials.
	ClientID string `yaml:"client-id"`

	// ClientSecret contains a password type Application Secret for
	// the application as generated on
	// https://console.developers.google.com/apis/credentials.
	ClientSecret string `yaml:"client-secret"`
}

// NewIdentityProvider creates a google identity provider with the
// configuration defined by p.
func NewIdentityProvider(p Params) idp.IdentityProvider {
	return openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Name:         "google",
		Issuer:       "https://accounts.google.com",
		Domain:       "google",
		Scopes:       []string{oidc.ScopeOpenID, "email"},
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
	})
}
