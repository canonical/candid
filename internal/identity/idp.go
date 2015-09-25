// Copyright 2015 Canonical Ltd.

package identity

import (
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/idp"
	intidp "github.com/CanonicalLtd/blues-identity/internal/idp"
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
	URL(c intidp.Context, waitid string) (string, error)

	// Handle handles any requests sent to the identity provider's
	// endpoints.
	//
	// The endpoints for the identity provider are currently created
	// at /v1/idp/{{.Name}}/ although the identity provider should
	// not rely on that being the case. Definitive URLs can be obrain
	// from c.IDPURL(). The provider specific path can be obtained
	// from c.Params().PathVar.Get("path").
	Handle(c intidp.Context)
}

// newIDP creates a new IdentityProvider from the provided specification.
func newIDP(sp ServerParams, p idp.IdentityProvider) (IdentityProvider, error) {
	switch p.Type {
	case idp.UbuntuSSO:
		return intidp.NewUSSOIdentityProvider(), nil
	case idp.UbuntuSSOOAuth:
		return &intidp.USSOOAuthIdentityProvider{}, nil
	case idp.Agent:
		return intidp.NewAgentIdentityProvider(sp.Location)
	case idp.Keystone:
		return intidp.NewKeystoneIdentityProvider(p.Config.(*idp.KeystoneParams)), nil
	case idp.KeystoneUserpass:
		return intidp.NewKeystoneUserpassIdentityProvider(p.Config.(*idp.KeystoneParams)), nil
	case idp.KeystoneToken:
		return intidp.NewKeystoneTokenIdentityProvider(p.Config.(*idp.KeystoneParams)), nil
	default:
		return nil, errgo.Newf("unknown provider type %q", p.Type)
	}
}
