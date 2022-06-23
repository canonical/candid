// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package openid provides identity providers that use OpenID to
// determine the identity.
package openid

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/coreos/go-oidc"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juju/loggo"
	"github.com/juju/names/v4"
	"golang.org/x/oauth2"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

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

// An IdentityCreator is used to create a candid identity from the
// OAuth2 token returned by the OAuth2 authentication process.
type IdentityCreator interface {
	// Create an identity using the provided token. The identity must
	// include a ProviderID which will remain constant for all
	// authentications made by the same user, it is recommended that the
	// ProviderID function is used for this purpose.
	//
	// If the identity includes a username then that username will be
	// used as the default when creating a new user. If a user already
	// exists that are identified by the ProviderID then the username
	// will not be updated.
	//
	// If the Name or Email values are non-zero these values will either
	// replace any currently stored values, or be used as defaults when
	// registering a new user.
	CreateIdentity(context.Context, *oauth2.Token) (store.Identity, error)
}

// A GroupsRetriever is used to retrieve a list of user groups from the
// OpenID token returned by the OpenID authentication process.
type GroupsRetriever interface {
	// RetrieveGroups retrieves groups from the OpenID token.
	RetrieveGroups(context.Context, *oauth2.Token, func(interface{}) error) ([]string, error)
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

	// MatchEmailAddr is a regular expression that is used to determine if
	// this identity provider can be used for a particular user email.
	MatchEmailAddr string `yaml:"match-email-addr"`

	// IdentityCreator is the IdentityCreator that the identity provider
	// will use to convert the OAuth2 token into a candid Identity. If
	// this is nil the default implementation provided by the
	// openIDConnect identity provider will be used.
	IdentityCreator IdentityCreator

	// GroupsRetriever is the GroupsRetriever that the identity provider
	// will use to retrieve a list of groups from the OAuth2 token. If
	// this is nil the default implementation provided by the
	// openIDConnect identity provider will be used.
	GroupsRetriever GroupsRetriever
}

// NewOpenIDConnectIdentityProvider creates a new identity provider using
// OpenID connect.
func NewOpenIDConnectIdentityProvider(params OpenIDConnectParams) idp.IdentityProvider {
	if params.Description == "" {
		params.Description = params.Name
	}
	if params.Icon == "" {
		params.Icon = "/static/images/icons/openid.svg"
	}
	if len(params.Scopes) == 0 {
		params.Scopes = []string{oidc.ScopeOpenID}
	}

	var matchEmailAddr *regexp.Regexp
	if params.MatchEmailAddr != "" {
		var err error
		matchEmailAddr, err = regexp.Compile(params.MatchEmailAddr)
		if err != nil {
			// if the email address matcher doesn't compile log the error but
			// carry on. A regular expression that doesn't compile also doesn't
			// match anything.
			logger.Errorf("cannot compile match-email-addr regular expression: %s", err)
		}
	}

	return &openidConnectIdentityProvider{
		params:         params,
		matchEmailAddr: matchEmailAddr,
	}
}

type openidConnectIdentityProvider struct {
	params         OpenIDConnectParams
	initParams     idp.InitParams
	provider       *oidc.Provider
	config         *oauth2.Config
	matchEmailAddr *regexp.Regexp
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

// IsForEmailAddr returns true when the identity provider should be used
// to identify a user with the given email address.
func (idp *openidConnectIdentityProvider) IsForEmailAddr(addr string) bool {
	if idp.matchEmailAddr == nil {
		return false
	}
	return idp.matchEmailAddr.MatchString(addr)
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
func (idp *openidConnectIdentityProvider) GetGroups(_ context.Context, identity *store.Identity) ([]string, error) {
	return identity.Groups, nil
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

	ic := idp.params.IdentityCreator
	if ic == nil {
		ic = idp
	}
	user, err := ic.CreateIdentity(ctx, tok)
	if err != nil {
		return errgo.Mask(err)
	}

	existingUser := store.Identity{
		ProviderID: user.ProviderID,
	}
	err = idp.initParams.Store.Identity(ctx, &existingUser)
	if err == nil {
		var upd store.Update
		// A user exists check if it needs updating.
		if user.Name != "" && existingUser.Name != user.Name {
			existingUser.Name = user.Name
			upd[store.Name] = store.Set
		}
		if user.Email != "" && existingUser.Email != user.Email {
			existingUser.Email = user.Email
			upd[store.Email] = store.Set
		}
		if !cmp.Equal(user.Groups, existingUser.Groups, cmpopts.SortSlices(func(a, b string) bool { return a < b })) {
			existingUser.Groups = user.Groups
			upd[store.Groups] = store.Set
		}
		if (upd != store.Update{}) {
			err = idp.initParams.Store.UpdateIdentity(ctx, &existingUser, upd)
		}
		if err == nil {
			idp.initParams.VisitCompleter.RedirectSuccess(ctx, w, req, ls.ReturnTo, ls.State, &existingUser)
			return nil
		}
	}
	if errgo.Cause(err) != store.ErrNotFound {
		return errgo.Mask(err)
	}

	// The user needs to be created.
	if user.Username != "" {
		// Attempt to create a user with the preferred username.
		err := idp.initParams.Store.UpdateIdentity(ctx, &user, store.Update{
			store.Username: store.Set,
			store.Name:     store.Set,
			store.Email:    store.Set,
			store.Groups:   store.Set,
		})
		if err == nil {
			idp.initParams.VisitCompleter.RedirectSuccess(ctx, w, req, ls.ReturnTo, ls.State, &user)
			return nil
		}
		if errgo.Cause(err) != store.ErrDuplicateUsername {
			return errgo.Mask(err)
		}
	}

	// The user needs to register.
	ls.ProviderID = user.ProviderID
	cookiePath := idputil.CookiePathRelativeToLocation(idputil.LoginCookiePath, idp.initParams.Location, idp.initParams.SkipLocationForCookiePaths)
	state, err := idp.initParams.Codec.SetCookie(w, idputil.LoginCookieName, cookiePath, ls)
	if err != nil {
		return errgo.Mask(err)
	}

	groups, err := idputil.WriteGroupsToCSV(user.Groups)
	if err != nil {
		return errgo.Mask(err)
	}
	return errgo.Mask(idputil.RegistrationForm(ctx, w, idputil.RegistrationParams{
		State:    state,
		Domain:   idp.params.Domain,
		FullName: user.Name,
		Email:    user.Email,
		Groups:   groups,
	}, idp.initParams.Template))
}

func (idp *openidConnectIdentityProvider) register(ctx context.Context, w http.ResponseWriter, req *http.Request, ls idputil.LoginState) error {
	groups, err := idputil.ReadGroupsFromCSV(req.Form.Get("groups"))
	if err != nil {
		return errgo.Mask(err)
	}

	u := &store.Identity{
		ProviderID: ls.ProviderID,
		Name:       req.Form.Get("fullname"),
		Email:      req.Form.Get("email"),
		Groups:     groups,
	}
	err = idp.registerUser(ctx, req.Form.Get("username"), u)
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
		Groups:   req.Form.Get("groups"),
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
		store.Groups:   store.Set,
	})
	if err == nil {
		return nil
	}
	if errgo.Cause(err) != store.ErrDuplicateUsername {
		return errgo.Mask(err)
	}
	return errgo.WithCausef(nil, errInvalidUser, "Username already taken, please pick a different one.")
}

// CreateIdentity is the default implementation of an IdentityCreator.
// CreateIdentity creates the identity from the "id_token" attached to
// the given token. The ProviderID will be created using the ProviderID
// function. The Username, Name & Email values will be taken from the
// claims "preferred_username", "name" & "email" if they are present.
func (idp *openidConnectIdentityProvider) CreateIdentity(ctx context.Context, tok *oauth2.Token) (store.Identity, error) {
	idtok := tok.Extra("id_token")
	if idtok == nil {
		return store.Identity{}, errgo.Newf("no id_token in OpenID response")
	}
	idtoks, ok := idtok.(string)
	if !ok {
		return store.Identity{}, errgo.Newf("invalid id_token in OpenID response")
	}
	id, err := idp.provider.Verifier(&oidc.Config{ClientID: idp.config.ClientID}).Verify(ctx, idtoks)
	if err != nil {
		return store.Identity{}, errgo.Mask(err)
	}

	user := store.Identity{
		ProviderID: ProviderID(idp.Name(), id),
	}
	var claims claims
	if err := id.Claims(&claims); err == nil {
		if names.IsValidUserName(claims.PreferredUsername) {
			user.Username = joinDomain(claims.PreferredUsername, idp.Domain())
		}
		user.Email = claims.Email
		user.Name = claims.FullName

		if idp.params.GroupsRetriever != nil {
			if user.Groups, err = idp.params.GroupsRetriever.RetrieveGroups(ctx, tok, id.Claims); err != nil {
				return store.Identity{}, errgo.Notef(err, "failed to retrieve groups from an OpenID response")
			}
		} else {
			user.Groups = claims.Groups
		}
	}

	return user, nil
}

// claims contains the set of claims possibly returned in the OpenID
// token.
type claims struct {
	FullName          string   `json:"name"`
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
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

// ProviderID creates a ProviderIdentity using the Subject and Issuer
//from the given ID token.
func ProviderID(provider string, id *oidc.IDToken) store.ProviderIdentity {
	return store.MakeProviderIdentity(provider, fmt.Sprintf("%s:%s", id.Issuer, id.Subject))
}
