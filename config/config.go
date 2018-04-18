// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// The config package defines configuration parameters for the id server.
package config

import (
	"crypto/tls"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/candid/idp"
)

type StorageKind int

const (
	MongoStorage StorageKind = iota
	PostgresStorage
	MemStorage
)

var logger = loggo.GetLogger("candid.config")

// Config holds the configuration parameters for the identity service.
type Config struct {
	// The following three fields are mutually exclusive. Exactly one
	// of them must be non-zero to specify the storage backend to use.

	// MongoAddr holds the MongoDB server address.
	MongoAddr string `yaml:"mongo-addr"`

	// PostgresConnectionString holds the string to use to make a database connection
	// to Postgres. Environment variables are also consulted.
	PostgresConnectionString string `yaml:"postgres-connection-string"`

	// EphemeralStorage specifies that in-memory storage should be used.
	// This is generally only useful for tests.
	EphemeralStorage bool `yaml:"ephemeral-storage"`

	// StorageKind specifies the kind of storage to use.
	// This is inferred from the above three fields when parsing the
	// configuration.
	StorageKind StorageKind `yaml:"-"`

	// LoggingConfig holds the loggo configuration to use.
	LoggingConfig string `yaml:"logging-config"`

	// APIAddr holds the address to listen on for HTTP connections to the Candid API
	// formatted as hostname:port.
	APIAddr string `yaml:"api-addr"`

	// Location holds the external address to use when the API
	// returns references to itself (for example in third party caveat locations).
	Location string `yaml:"location"`

	// AccessLog holds the name of a file to use to write logs of API accesses.
	AccessLog string `yaml:"access-log"`

	// MaxMgoSessions holds the maximum number of Mongo sessions
	// to use when the MongoDB storage backend is used.
	// TODO this is currently ignored.
	MaxMgoSessions int `yaml:"max-mgo-sessions"`

	// RendezvousTimeout holds length of time that an interactive authentication
	// request can be active before it is forgotten.
	RendezvousTimeout DurationString `yaml:"rendezvous-timeout"`

	// IdentityProviders holds all the configured identity providers.
	// If this is empty, the default Ubuntu SSO (USSO) provider will be used.
	IdentityProviders []IdentityProvider `yaml:"identity-providers"`

	// PrivateAddr holds the hostname where this instance of the Candid server
	// can be contacted. This is used by instances of the Candid server
	// to communicate directly with one another.
	PrivateAddr string `yaml:"private-addr"`

	// TLSCert and TLSKey hold a TLS server certificate for the HTTP
	// server to use. If these are specified, Candid will serve its API
	// over HTTPS using them.
	TLSCert string `yaml:"tls-cert"`
	TLSKey  string `yaml:"tls-key"`

	// PublicKey and PrivateKey holds the key pair used by the Candid
	// server for encryption and decryption of third party caveats.
	// These must be specified.
	// TODO generate these automatically if not specified and store
	// them in the database.
	PublicKey  *bakery.PublicKey  `yaml:"public-key"`
	PrivateKey *bakery.PrivateKey `yaml:"private-key"`

	// AdminAgentPublicKey holds the public part of a key pair that
	// can be used to authenticate as the admin user. If not specified
	// no public-key-based authentication can be used for the admin
	// user.
	AdminAgentPublicKey *bakery.PublicKey `yaml:"admin-agent-public-key"`

	// AdminPassword holds the password for basic-auth admin
	// access. If this is empty, no basic-auth authentication will
	// be allowed.
	AdminPassword string `yaml:"admin-password"`

	// ResourcePath holds the path to the directory holding
	// resources used by the server, including web page templates.
	ResourcePath string `yaml:"resource-path"`

	// HTTPProxy holds the address of an HTTP proxy to use for
	// outgoing HTTP requests, in the same form as the HTTP_PROXY
	// environment variable.
	HTTPProxy string `yaml:"http-proxy"`

	// NoProxy holds which hosts not to use the HTTProxy for,
	// in the same form as the NO_PROXY environment variable.
	NoProxy string `yaml:"no-proxy"`
}

// TLSConfig returns a TLS configuration to be used for serving
// the API. If the TLS certficate and key are not specified, it returns nil.
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
	if c.APIAddr == "" {
		missing = append(missing, "api-addr")
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
	if c.PrivateAddr == "" {
		missing = append(missing, "private-addr")
	}
	storageFieldNames := []string{
		MongoStorage:    "mongo-addr",
		PostgresStorage: "postgres-connection-string",
		MemStorage:      "ephemeral-storage",
	}
	storageMethods := []bool{
		MongoStorage:    c.MongoAddr != "",
		PostgresStorage: c.PostgresConnectionString != "",
		MemStorage:      c.EphemeralStorage,
	}
	storageCount := 0
	for i, isSet := range storageMethods {
		if isSet {
			c.StorageKind = StorageKind(i)
			storageCount++
		}
	}
	if storageCount == 0 {
		missing = append(missing, strings.Join(storageFieldNames, " or "))
	}
	if len(missing) != 0 {
		return errgo.Newf("missing fields %s in config file", strings.Join(missing, ", "))
	}
	if storageCount > 1 {
		return errgo.Newf("more than one of %s specified", strings.Join(storageFieldNames, " or "))
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

// DurationString holds a duration that marshals and unmarshals as a
// string in the form printed by time.Duration.String.
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
