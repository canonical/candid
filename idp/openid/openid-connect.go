// Copyright 2017 Canonical Ltd.

// Package openid provides identity providers that use OpenID to
// determine the identity.
package openid

import (
	"fmt"
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/juju/idmclient/params"
	"golang.org/x/oauth2"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/names.v2"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
)

type OpenIDConnectParams struct {
	// Name is the name that will be given to the identity provider.
	Name string

	// Description is the description that will be used with the
	// identity provider. If this is not set then Name will be used.
	Description string

	// Domain is the domain with which all identities created by this
	// identity provider will be tagged (not including the @ separator).
	Domain string

	// Issuer is the OpenID connect issuer for the identity provider.
	// Discovery will be performed for this issuer.
	Issuer string

	// ClientID is the ID of the client as registered with the issuer.
	ClientID string

	// ClientSecret is a client specific secret agreed with the issuer.
	ClientSecret string
}

// NewOpenIDConnectIdentityProvider creates a new identity provider using
// OpenID connect.
func NewOpenIDConnectIdentityProvider(params OpenIDConnectParams) idp.IdentityProvider {
	if params.Description == "" {
		params.Description = params.Name
	}
	return &openidConnectIdentityProvider{
		params: params,
	}
}

type openidConnectIdentityProvider struct {
	params   OpenIDConnectParams
	provider *oidc.Provider
	config   *oauth2.Config
}

// Name implements idp.IdentityProvider.Name.
func (idp *openidConnectIdentityProvider) Name() string {
	return idp.params.Name
}

// Description implements idp.IdentityProvider.Description.
func (idp *openidConnectIdentityProvider) Description() string {
	return idp.params.Description
}

// Interactive implements idp.IdentityProvider.Interactive.
func (*openidConnectIdentityProvider) Interactive() bool {
	return true
}

// URL implements idp.IdentityProvider.URL.
func (*openidConnectIdentityProvider) URL(ctx idp.Context, waitID string) string {
	return idputil.URL(ctx, "/login", waitID)
}

// Init implements idp.IdentityProvider.Init by performing discovery on
// the issuer and set up the identity provider.
func (idp *openidConnectIdentityProvider) Init(ctx idp.Context) error {
	var err error
	idp.provider, err = oidc.NewProvider(ctx, idp.params.Issuer)
	if err != nil {
		return errgo.Mask(err)
	}
	idp.config = &oauth2.Config{
		ClientID:     idp.params.ClientID,
		ClientSecret: idp.params.ClientSecret,
		Endpoint:     idp.provider.Endpoint(),
		RedirectURL:  ctx.URL("/callback"),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}
	if err := ctx.Database().C("states").EnsureIndex(mgo.Index{Key: []string{"created"}, ExpireAfter: time.Hour}); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// Handle implements idp.IdentityProvider.Handle.
func (idp *openidConnectIdentityProvider) Handle(ctx idp.RequestContext, w http.ResponseWriter, req *http.Request) {
	switch ctx.Path() {
	case "/callback":
		if waitid, err := idp.callback(ctx, w, req); err != nil {
			ctx.LoginFailure(waitid, err)
		}
	default:
		if err := idp.login(ctx, w, req); err != nil {
			ctx.LoginFailure(idputil.WaitID(req), err)
		}
	}
}

func (idp *openidConnectIdentityProvider) login(ctx idp.RequestContext, w http.ResponseWriter, req *http.Request) error {
	state := state{
		ID:      bson.NewObjectId(),
		WaitID:  idputil.WaitID(req),
		Created: time.Now(),
	}
	if err := ctx.Database().C("states").Insert(state); err != nil {
		return errgo.Mask(err)
	}
	url := idp.config.AuthCodeURL(state.ID.Hex())
	http.Redirect(w, req, url, http.StatusFound)
	return nil
}

func (idp *openidConnectIdentityProvider) callback(ctx idp.RequestContext, w http.ResponseWriter, req *http.Request) (string, error) {
	var state state
	if hex := req.Form.Get("state"); bson.IsObjectIdHex(hex) {
		if err := ctx.Database().C("states").FindId(bson.ObjectIdHex(hex)).One(&state); err != nil {
			return "", errgo.Notef(err, "cannot retrieve state %q", hex)
		}
	} else {
		return "", errgo.WithCausef(nil, params.ErrBadRequest, "invalid state %q", hex)
	}
	tok, err := idp.config.Exchange(ctx, req.Form.Get("code"))
	if err != nil {
		return state.WaitID, errgo.Mask(err)
	}
	idtok := tok.Extra("id_token")
	if idtok == nil {
		return state.WaitID, errgo.Newf("no id_token in OpenID response")
	}
	idtoks, ok := idtok.(string)
	if !ok {
		return state.WaitID, errgo.Newf("invalid id_token in OpenID response")
	}
	id, err := idp.provider.Verifier(&oidc.Config{ClientID: idp.config.ClientID}).Verify(ctx, idtoks)
	if err != nil {
		return state.WaitID, errgo.Mask(err)
	}
	externalID := fmt.Sprintf("openid-connect:%s:%s", id.Issuer, id.Subject)
	u, err := ctx.FindUserByExternalId(externalID)
	if err == nil {
		idputil.LoginUser(ctx, state.WaitID, w, u)
		return "", nil
	}
	if errgo.Cause(err) != params.ErrNotFound {
		return state.WaitID, errgo.Mask(err)
	}
	var claims claims
	if err := id.Claims(&claims); err != nil {
		return state.WaitID, errgo.Mask(err)
	}
	u = &params.User{
		ExternalID: externalID,
		Username:   joinDomain(sanitizeUsername(claims.PreferredUsername), idp.params.Domain),
		FullName:   claims.FullName,
		Email:      claims.Email,
	}
	if err := ctx.UpdateUser(u); err != nil {
		return state.WaitID, errgo.Mask(err)
	}
	idputil.LoginUser(ctx, state.WaitID, w, u)
	return "", nil
}

// state contains the stored state for the OAuth2 authoriaztion query
// used in the the OpenID login.
type state struct {
	ID      bson.ObjectId `bson:"_id"`
	WaitID  string
	Created time.Time
}

// claims contains the set of claims possibly returned in the OpenID
// token.
type claims struct {
	FullName          string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
}

// sanitizeUsername parses the given name and replaces any unsupported
// characters with a '+'.
//
// Note: it is quite possible that two users could generate the same
// username by this method.
//
// TODO(mhilton): allow users to choose their username.
func sanitizeUsername(name string) string {
	if names.IsValidUserName(name) {
		return name
	}
	buf := make([]byte, 0, len(name))
	for _, r := range name {
		switch {
		case 'A' <= r && r <= 'Z':
		case 'a' <= r && r <= 'z':
		case '0' <= r && r <= '9':
		case r == '.' || r == '-' || r == '+':
		default:
			r = '+'
		}
		buf = append(buf, byte(r))
	}
	return string(buf)
}

// joinDomain creates a new params.Username with the given name and
// (optional) domain.
func joinDomain(name, domain string) params.Username {
	if domain == "" {
		return params.Username(name)
	}
	return params.Username(fmt.Sprintf("%s@%s", name, domain))
}
