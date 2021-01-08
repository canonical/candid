// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package adfs is an identity provider that authenticates with an ADFS
// service.
package adfs

import (
	oidc "github.com/coreos/go-oidc"
	"gopkg.in/errgo.v1"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/openid"
)

func init() {
	idp.Register("adfs", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
		var p Params
		if err := unmarshal(&p); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal adfs parameters")
		}
		if p.URL == "" {
			return nil, errgo.Newf("url not specified")
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

	// URL is the URL of the Active Directory Federation Services
	// instance that is used to provide identities. OpenID Connect
	// discovery will be run on this URL to determine the required
	// service parameters.
	URL string `yaml:"url"`

	// ClientID contains the Application Id for the application.
	ClientID string `yaml:"client-id"`

	// ClientSecret contains a password type Application Secret for
	// the application.
	ClientSecret string `yaml:"client-secret"`

	// Hidden is set if the IDP should be hidden from interactive
	// prompts.
	Hidden bool `yaml:"hidden"`
}

// NewIdentityProvider creates an ADFS identity provider with the
// configuration defined by p.
func NewIdentityProvider(p Params) idp.IdentityProvider {
	if p.Name == "" {
		p.Name = "adfs"
	}
	if p.Domain == "" {
		p.Domain = p.Name
	}
	return openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Name:         p.Name,
		Issuer:       p.URL,
		Domain:       p.Domain,
		Description:  p.Description,
		Icon:         p.Icon,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Hidden:       p.Hidden,
	})
}
