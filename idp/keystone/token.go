// Copyright 2015 Canonical Ltd.

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
	config.RegisterIDP("keystone_token", constructor(NewTokenIdentityProvider))
}

// NewTokenIdentityProvider creates a idp.IdentityProvider which will
// authenticate against a keystone server using existing tokens.
func NewTokenIdentityProvider(p Params) idp.IdentityProvider {
	return &tokenIdentityProvider{
		identityProvider: newIdentityProvider(p),
	}
}

// tokenIdentityProvider is an identity provider that uses a configured
// keystone instance to authenticate against using an existing token to
// authenticate.
type tokenIdentityProvider struct {
	identityProvider
}

// Interactive implements idp.IdentityProvider.Interactive.
func (*tokenIdentityProvider) Interactive() bool {
	return false
}

// Handle implements idp.IdentityProvider.Handle.
func (idp *tokenIdentityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	var lr tokenLoginRequest
	if err := httprequest.Unmarshal(idputil.RequestParams(ctx, w, req), &lr); err != nil {
		idp.initParams.LoginCompleter.Failure(ctx, w, req, idputil.WaitID(req), errgo.WithCausef(err, params.ErrBadRequest, "cannot unmarshal login request"))
		return
	}
	idp.doLogin(ctx, w, req, keystone.Auth{
		Token: &keystone.Token{
			ID: lr.Token.Login.ID,
		},
	})
}

type tokenLoginRequest struct {
	httprequest.Route `httprequest:"POST"`
	Token             token `httprequest:",body"`
}

type idName struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// token is the token sent to use to login to the keystone
// server. The only part that is used is Login.ID.
type token struct {
	Login struct {
		Domain idName `json:"domain"`
		User   idName `json:"user"`
		Tenant idName `json:"tenant"`
		ID     string `json:"id"`
	} `json:"login"`
}
