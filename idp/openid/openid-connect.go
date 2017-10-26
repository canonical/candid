// Copyright 2017 Canonical Ltd.

// Package openid provides identity providers that use OpenID to
// determine the identity.
package openid

import (
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/names.v2"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
	"github.com/CanonicalLtd/blues-identity/idp/idputil/secret"
	"github.com/CanonicalLtd/blues-identity/store"
)

func init() {
	config.RegisterIDP("openid-connect", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
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
	codec      *secret.Codec
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

// Interactive implements idp.IdentityProvider.Interactive.
func (*openidConnectIdentityProvider) Interactive() bool {
	return true
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
	idp.codec = secret.NewCodec(idp.initParams.Key)
	return nil
}

// URL implements idp.IdentityProvider.URL.
func (idp *openidConnectIdentityProvider) URL(dischargeID string) string {
	return idputil.URL(idp.initParams.URLPrefix, "/login", dischargeID)
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
	switch req.URL.Path {
	case "/callback":
		if dischargeID, err := idp.callback(ctx, w, req); err != nil {
			idp.initParams.VisitCompleter.Failure(ctx, w, req, dischargeID, err)
		}
	case "/register":
		if dischargeID, err := idp.register(ctx, w, req); err != nil {
			idp.initParams.VisitCompleter.Failure(ctx, w, req, dischargeID, err)
		}
	default:
		if err := idp.login(ctx, w, req); err != nil {
			idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
		}
	}
}

func (idp *openidConnectIdentityProvider) login(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	dischargeID := idputil.DischargeID(req)
	err := idp.newSession(ctx, w, dischargeID)
	if err != nil {
		return errgo.Mask(err)
	}
	url := idp.config.AuthCodeURL(dischargeID)
	http.Redirect(w, req, url, http.StatusFound)
	return nil
}

func (idp *openidConnectIdentityProvider) callback(ctx context.Context, w http.ResponseWriter, req *http.Request) (string, error) {
	dischargeID, err := idp.getSession(ctx, req)
	if err != nil {
		return dischargeID, errgo.WithCausef(err, params.ErrBadRequest, "")
	}
	if dischargeID != req.Form.Get("state") {
		return dischargeID, errgo.WithCausef(nil, params.ErrBadRequest, "invalid session")
	}
	tok, err := idp.config.Exchange(ctx, req.Form.Get("code"))
	if err != nil {
		return dischargeID, errgo.Mask(err)
	}
	idtok := tok.Extra("id_token")
	if idtok == nil {
		return dischargeID, errgo.Newf("no id_token in OpenID response")
	}
	idtoks, ok := idtok.(string)
	if !ok {
		return dischargeID, errgo.Newf("invalid id_token in OpenID response")
	}
	id, err := idp.provider.Verifier(&oidc.Config{ClientID: idp.config.ClientID}).Verify(ctx, idtoks)
	if err != nil {
		return dischargeID, errgo.Mask(err)
	}
	user := store.Identity{
		ProviderID: store.MakeProviderIdentity(idp.Name(), fmt.Sprintf("%s:%s", id.Issuer, id.Subject)),
	}
	err = idp.initParams.Store.Identity(ctx, &user)
	if err == nil {
		idp.deleteSession(ctx, w)
		idp.initParams.VisitCompleter.Success(ctx, w, req, dischargeID, &user)
		return "", nil
	}

	if errgo.Cause(err) != store.ErrNotFound {
		return dischargeID, errgo.Mask(err)
	}
	var claims claims
	if err := id.Claims(&claims); err != nil {
		return dischargeID, errgo.Mask(err)
	}
	state, err := idp.codec.Encode(registrationState{
		WaitID:     dischargeID,
		ProviderID: user.ProviderID,
	})
	preferredUsername := ""
	if names.IsValidUserName(claims.PreferredUsername) {
		preferredUsername = claims.PreferredUsername
	}
	return dischargeID, errgo.Mask(idputil.RegistrationForm(ctx, w, idputil.RegistrationParams{
		State:    state,
		Username: preferredUsername,
		Domain:   idp.params.Domain,
		FullName: claims.FullName,
		Email:    claims.Email,
	}, idp.initParams.Template))
}

func (idp *openidConnectIdentityProvider) register(ctx context.Context, w http.ResponseWriter, req *http.Request) (string, error) {
	dischargeID, err := idp.getSession(ctx, req)
	if err != nil {
		return dischargeID, errgo.WithCausef(err, params.ErrBadRequest, "")
	}
	var state registrationState
	if err := idp.codec.Decode(req.Form.Get("state"), &state); err != nil {
		return dischargeID, errgo.WithCausef(err, params.ErrBadRequest, "invalid registration state")
	}
	if state.WaitID != dischargeID {
		return dischargeID, errgo.WithCausef(err, params.ErrBadRequest, "invalid registration state")
	}
	u := &store.Identity{
		ProviderID: state.ProviderID,
		Name:       req.Form.Get("fullname"),
		Email:      req.Form.Get("email"),
	}
	err = idp.registerUser(ctx, req.Form.Get("username"), u)
	if err == nil {
		idp.deleteSession(ctx, w)
		idp.initParams.VisitCompleter.Success(ctx, w, req, dischargeID, u)
		return dischargeID, nil
	}
	if errgo.Cause(err) != errInvalidUser {
		return dischargeID, errgo.Mask(err)
	}
	return dischargeID, errgo.Mask(idputil.RegistrationForm(ctx, w, idputil.RegistrationParams{
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

// newSession stores the state data for this login session in an
// encrypted session cookie.
func (idp *openidConnectIdentityProvider) newSession(ctx context.Context, w http.ResponseWriter, dischargeID string) error {
	sessionCookie := sessionCookie{
		WaitID:  dischargeID,
		Expires: time.Now().Add(15 * time.Minute),
	}
	value, err := idp.codec.Encode(sessionCookie)
	if err != nil {
		return errgo.Mask(err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:  idp.sessionCookieName(),
		Value: value,
	})
	return nil
}

// getSession retrieves and validats the current session cookie for the
// login session and returns the associated dischargeID.
func (idp *openidConnectIdentityProvider) getSession(ctx context.Context, req *http.Request) (string, error) {
	c, err := req.Cookie(idp.sessionCookieName())
	if err == http.ErrNoCookie {
		return "", errgo.Notef(err, "no login session")
	}
	if err != nil {
		return "", err
	}
	var sessionCookie sessionCookie
	if err = idp.codec.Decode(c.Value, &sessionCookie); err != nil {
		return "", errgo.Notef(err, "invalid session")
	}
	if sessionCookie.Expires.Before(time.Now()) {
		return "", errgo.New("expired session")
	}
	return sessionCookie.WaitID, nil
}

// deleteSession removes the session cookie for the current login
// session.
func (idp *openidConnectIdentityProvider) deleteSession(ctx context.Context, w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: idp.sessionCookieName(),
	})
}

func (idp *openidConnectIdentityProvider) sessionCookieName() string {
	return "idp-login-" + idp.params.Name
}

// sessionCookie contains the stored state for the OpenID login process.
type sessionCookie struct {
	WaitID  string    `json:"wid"`
	Expires time.Time `json:"exp"`
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
