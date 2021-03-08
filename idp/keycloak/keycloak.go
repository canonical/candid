// Copyright 2020 Mark Klein <mdklein@gmail.com>
// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package keycloak is an identity provider that authenticates with keycloak oidc.
package keycloak

import (
	oidc "github.com/coreos/go-oidc"
	"gopkg.in/errgo.v1"

	"gopkg.in/canonical/candid.v2/idp"
	"gopkg.in/canonical/candid.v2/idp/openid"
)

const (
	defaultProviderName   = "keycloak"
	defaultProviderDomain = "KEYCLOAK"
)

func init() {
	idp.Register("keycloak", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
		var p Params
		if err := unmarshal(&p); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal keycloak parameters")
		}
		if p.ClientID == "" {
			return nil, errgo.Newf("client-id not specified")
		}
		if p.KeycloakRealm == "" {
			return nil, errgo.Newf("keycloak-realm not specified")
		}
		return NewIdentityProvider(p), nil
	})
}

// Params is a struct containing the configuration data to register a keycloak identity Provider
type Params struct {
	// Name is the name that will be given to the identity provider.
	Name string `yaml:"name"`

	// Description is the description that will be used with the
	// identity provider. If this is not set then Name will be used.
	Description string `yaml:"description"`

	// Icon contains the URL or path of an icon.
	Icon string `yaml:"icon"`

	// Domain is the domain with which all identities created by this
	// identity provider will be tagged (not including the @ separator).
	Domain string `yaml:"domain"`

	// ClientID contains the Application Id for the application
	// registered
	ClientID string `yaml:"client-id"`

	// Optional: ClientSecret contains a password type Application Secret
	// for the application generated
	ClientSecret string `yaml:"client-secret"`

	// KeycloakReam contains the URI for the keycloak server
	// https://<keycloakserver>/auth/realms/<keycloakdomain>
	KeycloakRealm string `yaml:"keycloak-realm"`

	// Hidden is set if the IDP should be hidden from interactive
	// prompts.
	Hidden bool `yaml:"hidden"`
}

// NewIdentityProvider creates a keycloak identity provider with the
// configuration defined by p.
func NewIdentityProvider(p Params) idp.IdentityProvider {

	if p.Name == "" {
		p.Name = defaultProviderName
	}
	if p.Domain == "" {
		p.Domain = defaultProviderDomain
	}
	return openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Name:         p.Name,
		Issuer:       p.KeycloakRealm,
		Domain:       p.Domain,
		Description:  p.Description,
		Icon:         p.Icon,
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Hidden:       p.Hidden,
	})
}
