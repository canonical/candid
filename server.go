// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package candid

import (
	"html/template"
	"net/http"
	"sort"
	"time"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/juju/aclstore/v2"
	"github.com/juju/utils/v2/debugstatus"
	"gopkg.in/errgo.v1"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/agent"
	"github.com/canonical/candid/internal/debug"
	"github.com/canonical/candid/internal/discharger"
	"github.com/canonical/candid/internal/identity"
	"github.com/canonical/candid/internal/mfa"
	v1 "github.com/canonical/candid/internal/v1"
	"github.com/canonical/candid/meeting"
	"github.com/canonical/candid/store"
)

// Versions of the API that can be served.
const (
	Debug      = "debug"
	Discharger = "discharger"
	V1         = "v1"
)

var versions = map[string]identity.NewAPIHandlerFunc{
	Debug:      debug.NewAPIHandler,
	Discharger: discharger.NewAPIHandler,
	V1:         v1.NewAPIHandler,
}

// Versions returns all known API version strings in alphabetical order.
func Versions() []string {
	vs := make([]string, 0, len(versions))
	for v := range versions {
		vs = append(vs, v)
	}
	sort.Strings(vs)
	return vs
}

// ServerParams contains configuration parameters for a server.
type ServerParams struct {
	// MeetingStore holds the storage that will be used to store
	// rendezvous information.
	MeetingStore meeting.Store

	// ProviderDataStore holds the storeage that can be used by
	// identity providers to store data that is not associated with
	// an individual identity.
	ProviderDataStore store.ProviderDataStore

	// RootKeyStore holds the root key store that will be used to
	// store macaroon root keys within the identity server.
	RootKeyStore bakery.RootKeyStore

	// Store holds the identities store for the identity server.
	Store store.Store

	// AdminPassword holds the password for admin login.
	AdminPassword string

	// Key holds the keypair to use with the bakery service.
	Key *bakery.KeyPair

	// Location holds a URL representing the externally accessible
	// base URL of the service, without a trailing slash.
	Location string

	// PrivateAddr should hold a dialable address that will be used
	// for communication between identity servers. Note that this
	// should not contain a port.
	PrivateAddr string

	// IdentityProviders contains the set of identity providers that
	// should be initialised by the service.
	IdentityProviders []idp.IdentityProvider

	// MFAAuthenticator holds the multi-factor authenticator.
	MFAAuthenticator *mfa.Authenticator

	// DebugTeams contains the set of launchpad teams that may access
	// the restricted debug endpoints.
	// TODO remove this.
	DebugTeams []string

	// AdminAgentPublicKey contains the public key of the admin agent.
	AdminAgentPublicKey *bakery.PublicKey

	// StaticFileSystem contains an http.FileSystem that can be used
	// to serve static files.
	StaticFileSystem http.FileSystem

	// Template contains a set of templates that are used to generate
	// html output.
	Template *template.Template

	// DebugStatusCheckerFuncs contains functions that will be
	// executed as part of a /debug/status check.
	DebugStatusCheckerFuncs []debugstatus.CheckerFunc

	// RendezvousTimeout holds the time after which an interactive discharge wait
	// request will time out.
	RendezvousTimeout time.Duration

	// ACLStore holds the ACLStore for the identity server.
	ACLStore aclstore.ACLStore

	// RedirectLoginTrustedURLs contains a list of URLs that are
	// trusted to be used as return_to URLs during an interactive
	// login.
	RedirectLoginTrustedURLs []string

	// RedirectLoginTrustedDomains contains a list of domain names that
	// are fully trusted to be used as return_to URLs during an
	// interactive login. If the domain starts with the sequence "*."
	// then all subdomains of the subsequent domain will be trusted.
	RedirectLoginTrustedDomains []string

	// APIMacaroonTimeout is the maximum life of an API macaroon.
	APIMacaroonTimeout time.Duration

	// DischargeMacaroonTimeout is the maximum life of a Discharge
	// macaroon.
	DischargeMacaroonTimeout time.Duration

	// DischargeTokenTimeout is the maximum life of a Discharge
	// token.
	DischargeTokenTimeout time.Duration

	// SkipLocationForCookiePaths instructs if the Cookie Paths are to
	// be set relative to the Location Path or not.
	SkipLocationForCookiePaths bool

	// EnableEmailLogin enables the login with email address link on the
	// authentication required page.
	EnableEmailLogin bool
}

// NewServer returns a new handler that handles identity service requests and
// stores its data in the given database. The handler will serve the specified
// versions of the API.
func NewServer(params ServerParams, serveVersions ...string) (HandlerCloser, error) {
	// Remove the agent identity provider if it is specified as it is no longer used.
	idps := make([]idp.IdentityProvider, 0, len(params.IdentityProviders))
	for _, idp := range params.IdentityProviders {
		if idp == agent.IdentityProvider {
			continue
		}
		idps = append(idps, idp)
	}
	params.IdentityProviders = idps
	newAPIs := make(map[string]identity.NewAPIHandlerFunc)
	for _, vers := range serveVersions {
		newAPI := versions[vers]
		if newAPI == nil {
			return nil, errgo.Newf("unknown version %q", vers)
		}
		newAPIs[vers] = newAPI
	}
	return identity.New(identity.ServerParams(params), newAPIs)
}

type HandlerCloser interface {
	http.Handler
	Close()
}
