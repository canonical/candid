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

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/store"
)

var logger = loggo.GetLogger("candid.config")

// Config holds the configuration parameters for the identity service.
type Config struct {
	// Storage holds the storage backend to use.
	Storage *store.Config `yaml:"storage"`

	// IdentityProviders holds all the configured identity providers.
	// If this is empty, the default Ubuntu SSO (usso) provider will be used.
	IdentityProviders []idp.Config `yaml:"identity-providers"`

	// LoggingConfig holds the loggo configuration to use.
	LoggingConfig string `yaml:"logging-config"`

	// ListenAddress holds the address to listen on for HTTP connections to the Candid API
	// formatted as hostname:port.
	ListenAddress string `yaml:"listen-address"`

	// Location holds the external address to use when the API
	// returns references to itself (for example in third party caveat locations).
	Location string `yaml:"location"`

	// AccessLog holds the name of a file to use to write logs of API accesses.
	AccessLog string `yaml:"access-log"`

	// RendezvousTimeout holds length of time that an interactive authentication
	// request can be active before it is forgotten.
	RendezvousTimeout DurationString `yaml:"rendezvous-timeout"`

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

	// RedirectLoginWhitelist contains a list of URLs that are
	// trusted to be used as return_to URLs during an interactive
	// login.
	RedirectLoginWhitelist []string `yaml:"redirect-login-whitelist"`

	// RedirectLoginTrustedDomains contains a list of domains that are
	// trusted to be used as return_to URLs during an interactive
	// login.
	RedirectLoginTrustedDomains []string `yaml:"redirect-login-trusted-domains"`

	// APIMacaroonTimeout is the maximum age an API macaroon can get
	// before requiring re-authorization.
	APIMacaroonTimeout DurationString `yaml:"api-macaroon-timeout"`

	// DischargeMacaroonTimeout is the maximum age a discharge
	// macaroon can get before it becomes invalid.
	DischargeMacaroonTimeout DurationString `yaml:"discharge-macaroon-timeout"`

	// DischargeTokenTimeout is the maximum age a discharge token can
	// get before it becomes invalid.
	DischargeTokenTimeout DurationString `yaml:"discharge-token-timeout"`

	// SkipLocationForCookiePaths instructs if the Cookie Paths are to
	// be set relative to the Location Path or not.
	SkipLocationForCookiePaths bool `yaml:"skip-location-for-cookie-paths"`

	// EnableEmailLogin enables the login with email address link on the
	// authentication required page.
	EnableEmailLogin bool `yaml:"enable-email-login"`
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
	if c.Storage == nil {
		// TODO default to in-memory storage?
		missing = append(missing, "storage")
	}
	if c.ListenAddress == "" {
		missing = append(missing, "listen-address")
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
