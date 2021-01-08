// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package openid provides identity providers that use OpenID to
// determine the identity.
package openid

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/juju/loggo"
	"golang.org/x/oauth2"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/names.v2"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/idputil"
	"github.com/canonical/candid/store"
)

var logger = loggo.GetLogger("candid.idp.openid")

func init() {
	idp.Register("openid-connect", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
		var p OpenIDConnectParams
		if err := unmarshal(&p); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal openid-connect parameters")
		}
		if p.Name == "" {
			return nil, errgo.Newf("name not specified")
		}
		if p.Issuer == "" {
			return nil, errgo.Newf("issuer not specified")
		}
		if p.ClientID == "" {
			return nil, errgo.Newf("client-id not specified")
		}
		if p.ClientSecret == "" {
			return nil, errgo.Newf("client-secret not specified")
		}
		return NewOpenIDConnectIdentityProvider(p), nil
	})
}

type OpenIDConnectParams struct {
	// Name is the name that will be given to the identity provider.
	Name string `yaml:"name"`

	// Description is the description that will be used with the
	// identity provider. If this is not set then Name will be used.
	Description string `yaml:"description"`

	// Icon contains the URL or path of an icon.
	Icon string `yaml:"icon"`

	// Domain is the domain with which all identities created by this
	// identity provider will be tagged (not including the @ separator).
	Domain string `yaml:"domain"`

	// Issuer is the OpenID connect issuer for the identity provider.
	// Discovery will be performed for this issuer.
	Issuer string `yaml:"issuer"`

	// Scopes contains the OAuth scopes to request.
	Scopes []string `yaml:"scopes"`

	// ClientID is the ID of the client as registered with the issuer.
	ClientID string `yaml:"client-id"`

	// ClientSecret is a client specific secret agreed with the issuer.
	ClientSecret string `yaml:"client-secret"`

	// Hidden is set if the IDP should be hidden from interactive
	// prompts.
	Hidden bool `yaml:"hidden"`
}

// NewOpenIDConnectIdentityProvider creates a new identity provider using
// OpenID connect.
func NewOpenIDConnectIdentityProvider(params OpenIDConnectParams) idp.IdentityProvider {
	if params.Description == "" {
		params.Description = params.Name
	}
	if len(params.Scopes) == 0 {
		params.Scopes = []string{oidc.ScopeOpenID}
	}
	return &openidConnectIdentityProvider{
		params: params,
	}
}

type openidConnectIdentityProvider struct {
	params     OpenIDConnectParams
	initParams idp.InitParams
	provider   *oidc.Provider
	config     *oauth2.Config
}

// Name implements idp.IdentityProvider.Name.
func (idp *openidConnectIdentityProvider) Name() string {
	return idp.params.Name
}

// Domain implements idp.IdentityProvider.Domain.
func (idp *openidConnectIdentityProvider) Domain() string {
	return idp.params.Domain
}

// Description implements idp.IdentityProvider.Description.
func (idp *openidConnectIdentityProvider) Description() string {
	return idp.params.Description
}

// IconURL returns the URL of an icon for the identity provider.
func (idp *openidConnectIdentityProvider) IconURL() string {
	return idputil.ServiceURL(idp.initParams.Location, idp.params.Icon)
}

// Interactive implements idp.IdentityProvider.Interactive.
func (*openidConnectIdentityProvider) Interactive() bool {
	return true
}

// Hidden implements idp.IdentityProvider.Hidden.
func (idp *openidConnectIdentityProvider) Hidden() bool {
	return idp.params.Hidden
}

// Init implements idp.IdentityProvider.Init by performing discovery on
// the issuer and set up the identity provider.
func (idp *openidConnectIdentityProvider) Init(ctx context.Context, params idp.InitParams) error {
	idp.initParams = params
	var err error
	idp.provider, err = oidc.NewProvider(ctx, idp.params.Issuer)
	if err != nil {
		return errgo.Mask(err)
	}
	idp.config = &oauth2.Config{
		ClientID:     idp.params.ClientID,
		ClientSecret: idp.params.ClientSecret,
		Endpoint:     idp.provider.Endpoint(),
		RedirectURL:  idp.initParams.URLPrefix + "/callback",
		Scopes:       idp.params.Scopes,
	}
	return nil
}

// URL implements idp.IdentityProvider.URL.
func (idp *openidConnectIdentityProvider) URL(state string) string {
	return idputil.RedirectURL(idp.initParams.URLPrefix, "/login", state)
}

// SetInteraction implements idp.IdentityProvider.SetInteraction.
func (idp *openidConnectIdentityProvider) SetInteraction(ierr *httpbakery.Error, dischargeID string) {
}

//  GetGroups implements idp.IdentityProvider.GetGroups.
func (*openidConnectIdentityProvider) GetGroups(context.Context, *store.Identity) ([]string, error) {
	return nil, nil
}

// Handle implements idp.IdentityProvider.Handle.
func (idp *openidConnectIdentityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	var ls idputil.LoginState
	if err := idp.initParams.Codec.Cookie(req, idputil.LoginCookieName, req.Form.Get("state"), &ls); err != nil {
		logger.Infof("Invalid login state: %s", err)
		idputil.BadRequestf(w, "Login failed: invalid login state")
		return
	}
	switch req.URL.Path {
	case "/callback":
		if err := idp.callback(ctx, w, req, ls); err != nil {
			idp.initParams.VisitCompleter.RedirectFailure(ctx, w, req, ls.ReturnTo, ls.State, err)
		}
	case "/register":
		if err := idp.register(ctx, w, req, ls); err != nil {
			idp.initParams.VisitCompleter.RedirectFailure(ctx, w, req, ls.ReturnTo, ls.State, err)
		}
	default:
		idp.login(ctx, w, req)
	}
}

func (idp *openidConnectIdentityProvider) login(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, idp.config.AuthCodeURL(idputil.State(req)), http.StatusFound)
}

func (idp *openidConnectIdentityProvider) callback(ctx context.Context, w http.ResponseWriter, req *http.Request, ls idputil.LoginState) error {
	tok, err := idp.config.Exchange(ctx, req.Form.Get("code"))
	if err != nil {
		return errgo.Mask(err)
	}
	idtok := tok.Extra("id_token")
	if idtok == nil {
		return errgo.Newf("no id_token in OpenID response")
	}
	idtoks, ok := idtok.(string)
	if !ok {
		return errgo.Newf("invalid id_token in OpenID response")
	}
	id, err := idp.provider.Verifier(&oidc.Config{ClientID: idp.config.ClientID}).Verify(ctx, idtoks)
	if err != nil {
		return errgo.Mask(err)
	}
	user := store.Identity{
		ProviderID: store.MakeProviderIdentity(idp.Name(), fmt.Sprintf("%s:%s", id.Issuer, id.Subject)),
	}
	err = idp.initParams.Store.Identity(ctx, &user)
	if err == nil {
		idp.initParams.VisitCompleter.RedirectSuccess(ctx, w, req, ls.ReturnTo, ls.State, &user)
		return nil
	}

	if errgo.Cause(err) != store.ErrNotFound {
		return errgo.Mask(err)
	}
	var claims claims
	if err := id.Claims(&claims); err != nil {
		return errgo.Mask(err)
	}
	ls.ProviderID = user.ProviderID
	state, err := idp.initParams.Codec.SetCookie(w, idputil.LoginCookieName, idputil.CookiePathRelativeToLocation(idputil.LoginCookiePath, idp.initParams.Location), ls)
	if err != nil {
		return errgo.Mask(err)
	}
	preferredUsername := ""
	if names.IsValidUserName(claims.PreferredUsername) {
		preferredUsername = claims.PreferredUsername
	}
	return errgo.Mask(idputil.RegistrationForm(ctx, w, idputil.RegistrationParams{
		State:    state,
		Username: preferredUsername,
		Domain:   idp.params.Domain,
		FullName: claims.FullName,
		Email:    claims.Email,
	}, idp.initParams.Template))
}

func (idp *openidConnectIdentityProvider) register(ctx context.Context, w http.ResponseWriter, req *http.Request, ls idputil.LoginState) error {
	u := &store.Identity{
		ProviderID: ls.ProviderID,
		Name:       req.Form.Get("fullname"),
		Email:      req.Form.Get("email"),
	}
	err := idp.registerUser(ctx, req.Form.Get("username"), u)
	if err == nil {
		idp.initParams.VisitCompleter.RedirectSuccess(ctx, w, req, ls.ReturnTo, ls.State, u)
		return nil
	}
	if errgo.Cause(err) != errInvalidUser {
		return errgo.Mask(err)
	}
	return errgo.Mask(idputil.RegistrationForm(ctx, w, idputil.RegistrationParams{
		State:    req.Form.Get("state"),
		Error:    err.Error(),
		Username: req.Form.Get("username"),
		Domain:   idp.params.Domain,
		FullName: req.Form.Get("fullname"),
		Email:    req.Form.Get("email"),
	}, idp.initParams.Template))
}

var errInvalidUser = errgo.New("invalid user")

func (idp *openidConnectIdentityProvider) registerUser(ctx context.Context, username string, u *store.Identity) error {
	if !names.IsValidUserName(username) {
		return errgo.WithCausef(nil, errInvalidUser, "invalid user name. The username must contain only A-Z, a-z, 0-9, '.', '-', & '+', and must start and end with a letter or number.")
	}
	if idputil.ReservedUsernames[username] {
		return errgo.WithCausef(nil, errInvalidUser, "username %s is not allowed, please choose another.", username)
	}
	u.Username = joinDomain(username, idp.params.Domain)
	err := idp.initParams.Store.UpdateIdentity(ctx, u, store.Update{
		store.Username: store.Set,
		store.Name:     store.Set,
		store.Email:    store.Set,
	})
	if err == nil {
		return nil
	}
	if errgo.Cause(err) != store.ErrDuplicateUsername {
		return errgo.Mask(err)
	}
	return errgo.WithCausef(nil, errInvalidUser, "Username already taken, please pick a different one.")
}

// claims contains the set of claims possibly returned in the OpenID
// token.
type claims struct {
	FullName          string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
}

// joinDomain creates a new params.Username with the given name and
// (optional) domain.
func joinDomain(name, domain string) string {
	if domain == "" {
		return name
	}
	return fmt.Sprintf("%s@%s", name, domain)
}

// registrationState holds state information about a registration that is
// in progress.
type registrationState struct {
	WaitID     string                 `json:"wid"`
	ProviderID store.ProviderIdentity `json:"pid"`
}
