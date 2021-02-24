// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package azure is an identity provider that authenticates with azure.
package azure

import (
	oidc "github.com/coreos/go-oidc"
	"gopkg.in/errgo.v1"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/openid"
)

func init() {
	idp.Register("azure", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
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
	// registered at https://apps.dev.microsoft.com.
	ClientID string `yaml:"client-id"`

	// ClientSecret contains a password type Application Secret for
	// the application as generated on
	// https://apps.dev.microsoft.com.
	ClientSecret string `yaml:"client-secret"`

	// Hidden is set if the IDP should be hidden from interactive
	// prompts.
	Hidden bool `yaml:"hidden"`
}

// NewIdentityProvider creates an azure identity provider with the
// configuration defined by p.
func NewIdentityProvider(p Params) idp.IdentityProvider {
	if p.Name == "" {
		p.Name = "azure"
	}
	if p.Domain == "" {
		p.Domain = "azure"
	}
	if p.Icon == "" {
		p.Icon = "/static/images/icons/azure.svg"
	}

	return openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Name:         p.Name,
		Issuer:       "https://login.live.com",
		Description:  p.Description,
		Icon:         p.Icon,
		Domain:       p.Domain,
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Hidden:       p.Hidden,
	})
}
