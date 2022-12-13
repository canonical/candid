// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/idputil"
	"github.com/canonical/candid/idp/keystone/internal/keystone"
	"github.com/canonical/candid/params"
)

func init() {
	idp.Register("keystone_token", constructor(NewTokenIdentityProvider))
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

// SetInteraction implements idp.IdentityProvider.SetInteraction.
func (idp *tokenIdentityProvider) SetInteraction(ierr *httpbakery.Error, dischargeID string) {
	ierr.SetInteraction("token", TokenInteractionInfo{
		URL: idputil.URL(idp.initParams.URLPrefix, "/interact", dischargeID),
	})
}

// Handle implements idp.IdentityProvider.Handle.
func (idp *tokenIdentityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	var lr TokenLoginRequest
	if err := httprequest.Unmarshal(idputil.RequestParams(ctx, w, req), &lr); err != nil {
		idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), errgo.WithCausef(err, params.ErrBadRequest, "cannot unmarshal login request"))
		return
	}
	user, err := idp.doLogin(ctx, keystone.Auth{
		Token: &keystone.Token{
			ID: lr.Token.Login.ID,
		},
	})
	if err != nil {
		idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
		return
	}
	if strings.TrimPrefix(req.URL.Path, idp.initParams.URLPrefix) == "/interact" {
		dt, err := idp.initParams.DischargeTokenCreator.DischargeToken(ctx, user)
		if err != nil {
			idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
			return
		}
		httprequest.WriteJSON(w, http.StatusOK, TokenLoginResponse{
			DischargeToken: dt,
		})
	} else {
		idp.initParams.VisitCompleter.Success(ctx, w, req, idputil.DischargeID(req), user)
	}
}

// TokenLoginRequest is the request sent for a token login.
type TokenLoginRequest struct {
	httprequest.Route `httprequest:"POST"`
	Token             Token `httprequest:",body"`
}

// TokenLoginResponse is the response sent for a token login.
type TokenLoginResponse struct {
	DischargeToken *httpbakery.DischargeToken `json:"discharge-token"`
}

type idName struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// Token is the token sent to use to login to the keystone
// server. The only part that is used is Login.ID.
type Token struct {
	Login struct {
		Domain idName `json:"domain"`
		User   idName `json:"user"`
		Tenant idName `json:"tenant"`
		ID     string `json:"id"`
	} `json:"login"`
}

// TokenInteractionInfo is the interaction info for a token interactor.
type TokenInteractionInfo struct {
	URL string `json:"url"`
}
