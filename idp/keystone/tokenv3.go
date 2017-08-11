// Copyright 2016 Canonical Ltd.

package keystone

import (
	"net/http"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
	"github.com/CanonicalLtd/blues-identity/idp/keystone/internal/keystone"
)

func init() {
	config.RegisterIDP("keystonev3_token", constructor(NewV3TokenIdentityProvider))
}

// NewV3TokenIdentityProvider creates a idp.IdentityProvider which will
// authenticate against a keystone (version 3) server using existing
// tokens.
func NewV3TokenIdentityProvider(p Params) idp.IdentityProvider {
	return &v3tokenIdentityProvider{
		identityProvider: newIdentityProvider(p),
	}
}

// v3tokenIdentityProvider is an identity provider that uses a configured
// keystone instance to authenticate against using an existing token to
// authenticate.
type v3tokenIdentityProvider struct {
	identityProvider
}

// Interactive implements idp.IdentityProvider.Interactive.
func (*v3tokenIdentityProvider) Interactive() bool {
	return false
}

// Handle implements idp.IdentityProvider.Handle.
func (idp *v3tokenIdentityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	var lr tokenLoginRequest
	if err := httprequest.Unmarshal(idputil.RequestParams(ctx, w, req), &lr); err != nil {
		idp.initParams.LoginCompleter.Failure(ctx, w, req, idputil.WaitID(req), errgo.WithCausef(err, params.ErrBadRequest, "cannot unmarshal login request"))
		return
	}
	idp.doLoginV3(ctx, w, req, keystone.AuthV3{
		Identity: keystone.Identity{
			Methods: []string{"token"},
			Token: &keystone.IdentityToken{
				ID: lr.Token.Login.ID,
			},
		},
	})
}
