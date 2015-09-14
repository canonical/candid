// Copyright 2015 Canonical Ltd.

package idp

import "gopkg.in/errgo.v1"

const (
	UbuntuSSO        = "usso"
	UbuntuSSOOAuth   = "usso_oauth"
	Agent            = "agent"
	Keystone         = "keystone"
	KeystoneUserpass = "keystone_userpass"
)

// IdentityProvider describes the configuration of an Identity provider.
type IdentityProvider struct {
	Type   string
	Config interface{}
}

// UnmarshalYAML unmarshals an IdentityProvider from configuration made
// accessible through unmarshal. UnmarshalYAML implements
// yaml.Unmarshaler.
func (idp *IdentityProvider) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var t struct {
		Type string
	}
	if err := unmarshal(&t); err != nil {
		return errgo.Notef(err, "cannot unmarshal identity provider type")
	}
	switch t.Type {
	case UbuntuSSO:
		*idp = UbuntuSSOIdentityProvider
	case UbuntuSSOOAuth:
		*idp = UbuntuSSOOAuthIdentityProvider
	case Agent:
		*idp = AgentIdentityProvider
	case Keystone, KeystoneUserpass:
		var err error
		*idp, err = unmarshalKeystone(t.Type, unmarshal)
		if err != nil {
			return errgo.Notef(err, "cannot unmarshal keystone configuration")
		}
	default:
		return errgo.Newf("unrecognised identity provider type %q", t.Type)
	}
	return nil
}

// unmarshalKeystone unmarshals the configuration provided unmarshal.
// unmarshal is expected to behave in the way described in
// yaml.Unmarshaler.
func unmarshalKeystone(t string, unmarshal func(interface{}) error) (IdentityProvider, error) {
	var p KeystoneParams
	if err := unmarshal(&p); err != nil {
		return IdentityProvider{}, errgo.Mask(err)
	}
	if p.Name == "" {
		return IdentityProvider{}, errgo.Newf("name not specified")
	}
	if p.URL == "" {
		return IdentityProvider{}, errgo.Newf("url not specified")
	}
	return newKeystoneIdentityProvider(t, &p), nil
}

// UbuntuSSOIdentityProvider is an identity provider that uses Ubuntu
// SSO.
var UbuntuSSOIdentityProvider = IdentityProvider{
	Type: UbuntuSSO,
}

// UbuntuSSOOAuthIdentityProvider is an identity provider that uses
// Ubuntu SSO OAuth.
var UbuntuSSOOAuthIdentityProvider = IdentityProvider{
	Type: UbuntuSSOOAuth,
}

// AgentIdentityProvider is an identity provider that uses the agent
// login mechanism.
var AgentIdentityProvider = IdentityProvider{
	Type: Agent,
}

// KeystoneParams holds the parameters to use with a
// KeystoneIdentityProvider.
type KeystoneParams struct {
	Name        string `yaml:"name"`
	Domain      string `yaml:"domain"`
	Description string `yaml:"description"`
	URL         string `yaml:"url"`
}

// KeystoneIdentityProvider creates a new identity provider using a
// keystone service.
func KeystoneIdentityProvider(p *KeystoneParams) IdentityProvider {
	return newKeystoneIdentityProvider(Keystone, p)
}

// KeystoneUserpassIdentityProvider creates a new identity provider using a
// keystone service with a non-interactive interface.
func KeystoneUserpassIdentityProvider(p *KeystoneParams) IdentityProvider {
	return newKeystoneIdentityProvider(KeystoneUserpass, p)
}

// newKeystoneIdentityProvider creates a new identity provider using a
// keystone service with the specified type.
func newKeystoneIdentityProvider(t string, p *KeystoneParams) IdentityProvider {
	return IdentityProvider{
		Type:   t,
		Config: p,
	}
}
