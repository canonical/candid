// Copyright 2015 Canonical Ltd.

package idp

import "gopkg.in/errgo.v1"

// Type represents the type of identity provider.
type Type int

const (
	UbuntuSSO Type = iota
	UbuntuSSOOAuth
	Agent
	Keystone
)

var typeNames = map[string]Type{
	"usso":       UbuntuSSO,
	"usso_oauth": UbuntuSSOOAuth,
	"agent":      Agent,
	"keystone":   Keystone,
}

func (t *Type) UnmarshalText(text []byte) error {
	if tp, ok := typeNames[string(text)]; ok {
		*t = tp
		return nil
	}
	return errgo.Newf("unrecognised type %q", string(text))
}

// IdentityProvider describes the configuration of an Identity provider.
type IdentityProvider struct {
	Type   Type
	Config interface{}
}

// UnmarshalYAML unmarshals an IdentityProvider from a yaml object.
func (idp *IdentityProvider) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var t struct {
		Type Type
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
	case Keystone:
		var err error
		*idp, err = unmarshalKeystone(unmarshal)
		if err != nil {
			return errgo.Notef(err, "cannot unmarshal keystone configuration")
		}
	}
	return nil
}

// unmarshalKeystone unmarshals a YAML configuration into a keystone
// identity provider.
func unmarshalKeystone(unmarshal func(interface{}) error) (IdentityProvider, error) {
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
	return KeystoneIdentityProvider(&p), nil
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
	return IdentityProvider{
		Type:   Keystone,
		Config: p,
	}
}
