// Copyright 2014 Canonical Ltd.

// The config package defines configuration parameters for the id server.
package config

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/idp"
)

var logger = loggo.GetLogger("identity.config")

// Config holds the configuration parameters for the identity service.
type Config struct {
	MongoAddr           string             `yaml:"mongo-addr"`
	APIAddr             string             `yaml:"api-addr"`
	AuthUsername        string             `yaml:"auth-username"`
	AuthPassword        string             `yaml:"auth-password"`
	Location            string             `yaml:"location"`
	AccessLog           string             `yaml:"access-log"`
	MaxMgoSessions      int                `yaml:"max-mgo-sessions"`
	WaitTimeout         DurationString     `yaml:"wait-timeout"`
	IdentityProviders   []IdentityProvider `yaml:"identity-providers"`
	PrivateAddr         string             `yaml:"private-addr"`
	DebugTeams          []string           `yaml:"debug-teams"`
	TLSCert             string             `yaml:"tls-cert"`
	TLSKey              string             `yaml:"tls-key"`
	PublicKey           *bakery.PublicKey  `yaml:"public-key"`
	PrivateKey          *bakery.PrivateKey `yaml:"private-key"`
	AdminAgentPublicKey *bakery.PublicKey  `yaml:"admin-agent-public-key"`
	ResourcePath        string             `yaml:"resource-path"`
	HTTPProxy           string             `yaml:"http-proxy"`
	NoProxy             string             `yaml:"no-proxy"`
}

func (c *Config) TLSConfig() *tls.Config {
	if c.TLSCert == "" || c.TLSKey == "" {
		return nil
	}

	cert, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
	if err != nil {
		logger.Errorf("cannot create certificate: %s", err)
		return nil
	}
	return &tls.Config{
		Certificates: []tls.Certificate{
			cert,
		},
	}
}

func (c *Config) validate() error {
	var missing []string
	if c.MongoAddr == "" {
		missing = append(missing, "mongo-addr")
	}
	if c.APIAddr == "" {
		missing = append(missing, "api-addr")
	}
	if c.AuthUsername == "" {
		missing = append(missing, "auth-username")
	}
	if strings.Contains(c.AuthUsername, ":") {
		return fmt.Errorf("invalid user name %q (contains ':')", c.AuthUsername)
	}
	if c.AuthPassword == "" {
		missing = append(missing, "auth-password")
	}
	if c.PrivateKey == nil {
		missing = append(missing, "private-key")
	}
	if c.PublicKey == nil {
		missing = append(missing, "public-key")
	}
	if c.Location == "" {
		// TODO check it's a valid URL
		missing = append(missing, "location")
	}
	if c.MaxMgoSessions == 0 {
		missing = append(missing, "max-mgo-sessions")
	}
	if c.PrivateAddr == "" {
		missing = append(missing, "private-addr")
	}
	if len(missing) != 0 {
		return errgo.Newf("missing fields %s in config file", strings.Join(missing, ", "))
	}
	return nil
}

// Read reads an identity configuration file from the given path.
func Read(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errgo.Notef(err, "cannot open config file")
	}
	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read %q", path)
	}
	var conf Config
	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		return nil, errgo.Notef(err, "cannot parse %q", path)
	}
	if err := conf.validate(); err != nil {
		return nil, errgo.Mask(err)
	}
	return &conf, nil
}

// DurationString holds a duration that marshals and
// unmarshals as a friendly string.
type DurationString struct {
	time.Duration
}

func (dp *DurationString) UnmarshalText(data []byte) error {
	d, err := time.ParseDuration(string(data))
	if err != nil {
		return errgo.Mask(err)
	}
	dp.Duration = d
	return nil
}

// IdentityProvider represents a configured idp.IdentityProvider
type IdentityProvider struct {
	idp.IdentityProvider
}

var idps = make(map[string]func(func(interface{}) error) (idp.IdentityProvider, error))

func (idp *IdentityProvider) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var t struct {
		Type string
	}
	if err := unmarshal(&t); err != nil {
		return errgo.Notef(err, "cannot unmarshal identity provider type")
	}
	if idpf, ok := idps[t.Type]; ok {
		var err error
		idp.IdentityProvider, err = idpf(unmarshal)
		if err != nil {
			err = errgo.Notef(err, "cannot unmarshal %s configuration", t.Type)
		}
		return err
	}
	return errgo.Newf("unrecognised identity provider type %q", t.Type)
}

// RegisterIDP is used by identity providers to register a function that
// can be used to unmarshal an identity provider type. When the identity
// provider with the given name is used, the given function will be
// called to unmarshal its parameters from YAML. Its argument will be an
// unmarshalYAML function that can be used to unmarshal the configuration
// parameters into its argument according to the rules specified in
// gopkg.in/yaml.v2.
func RegisterIDP(idpType string, f func(func(interface{}) error) (idp.IdentityProvider, error)) {
	idps[idpType] = f
}
