// Copyright 2015 Canonical Ltd.

package identity

import (
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/internal/idp"
)

// IdentityProvider is the interface that is satisfied by all identity providers.
type IdentityProvider interface {
	// Name is the short name for the identity provider, this will
	// appear in urls.
	Name() string

	// Description is a name for the identity provider used to show
	// end users.
	Description() string

	// Interactive indicates whether log in is provided by the end
	// user interacting with the identity provider.
	Interactive() bool

	// URL provides the URL to use to begin a log-in to the identity provider.
	URL(c idp.Context, waitid string) (string, error)

	// Handle handles any requests sent to the identity provider's endpoints.
	Handle(c idp.Context)
}

// newIDP creates a new IdentityProvider from the provided specification.
func newIDP(t string, sp ServerParams, config interface{}) (IdentityProvider, error) {
	switch t {
	case "usso":
		return idp.NewUSSOIdentityProvider(), nil
	case "usso_oauth":
		return &idp.USSOOAuthIdentityProvider{}, nil
	case "agent":
		return idp.NewAgentIdentityProvider(sp.Location)
	default:
		return nil, errgo.Newf("unknown provider type %q", t)
	}
}
