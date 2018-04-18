package idp

import (
	"gopkg.in/errgo.v1"
)

// idps holds the registry of identity providers, indexed by idp type.
var idps = make(map[string]func(func(interface{}) error) (IdentityProvider, error))

// Config allows an IdentityProvider instance to be unmarshaled from a
// YAML configuration file. The "type" field determines which registered
// provider is used for the unmarshaling.
type Config struct {
	IdentityProvider
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var t struct {
		Type string
	}
	if err := unmarshal(&t); err != nil {
		return errgo.Notef(err, "cannot unmarshal identity provider type")
	}
	if idpf, ok := idps[t.Type]; ok {
		provider, err := idpf(unmarshal)
		if err != nil {
			return errgo.Notef(err, "cannot unmarshal %s configuration", t.Type)
		}
		c.IdentityProvider = provider
		return nil
	}
	return errgo.Newf("unrecognised identity provider type %q", t.Type)
}

// Register is used by identity providers to register a function that
// can be used to unmarshal an identity provider type. When the identity
// provider with the given name is used, f will be
// called to unmarshal its parameters from YAML. Its argument will be an
// unmarshalYAML function that can be used to unmarshal the configuration
// parameters into its argument according to the rules specified in
// gopkg.in/yaml.v2.
func Register(idpType string, f func(func(interface{}) error) (IdentityProvider, error)) {
	idps[idpType] = f
}
