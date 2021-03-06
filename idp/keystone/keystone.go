// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package keystone contains identity providers that validate against
// keystone servers.
package keystone

import (
	"context"
	"net/http"
	"strings"

	"github.com/juju/loggo"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"github.com/canonical/candid/v2/idp"
	"github.com/canonical/candid/v2/idp/idputil"
	"github.com/canonical/candid/v2/idp/keystone/internal/keystone"
	"github.com/canonical/candid/v2/params"
	"github.com/canonical/candid/v2/store"
)

var logger = loggo.GetLogger("candid.idp.keystone")

func init() {
	idp.Register("keystone", constructor(NewIdentityProvider))
}

// constructor returns a function that is suitable for passing to
// config.RegisterIDP that will decode and validate Params from YAML. If
// valid an identity provider will be created by calling f.
func constructor(f func(Params) idp.IdentityProvider) func(func(interface{}) error) (idp.IdentityProvider, error) {
	return func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
		var p Params
		if err := unmarshal(&p); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal keystone parameters")
		}
		if p.Name == "" {
			return nil, errgo.Newf("name not specified")
		}
		if p.URL == "" {
			return nil, errgo.Newf("url not specified")
		}
		return f(p), nil
	}
}

// Params holds the parameters to use with keystone identity providers.
type Params struct {
	// Name is the name that the identity provider will have within
	// the identity manager. The name is used as part of the url for
	// communicating with the identity provider.
	Name string `yaml:"name"`

	// If Domain is set it will be appended to any usernames or
	// groups provided by the identity provider. A user created by
	// this identity provide would be username@domain.
	Domain string `yaml:"domain"`

	// Description is a human readable description that will be used
	// if a list of providers is shown for a user to choose.
	Description string `yaml:"description"`

	// Icon contains the URL or path of an icon.
	Icon string `yaml:"icon"`

	// URL is the address of the keystone server.
	URL string `yaml:"url"`

	// Hidden is set if the IDP should be hidden from interactive
	// prompts.
	Hidden bool `yaml:"hidden"`
}

// NewIdentityProvider creates an interactive keystone identity provider
// with the configuration defined by p.
func NewIdentityProvider(p Params) idp.IdentityProvider {
	idp := newIdentityProvider(p)
	return &idp
}

// newIdentityProvider creates an identityProvider with the configuration
// defined by p.
func newIdentityProvider(p Params) identityProvider {
	if p.Description == "" {
		p.Description = p.Name
	}
	if p.Icon == "" {
		p.Icon = "/static/images/icons/keystone.svg"
	}
	return identityProvider{
		params: p,
		client: keystone.NewClient(p.URL),
	}
}

// identityProvider is an idp.IdentityProvider that authenticates against
// a keystone server.
type identityProvider struct {
	params     Params
	initParams idp.InitParams
	client     *keystone.Client
}

// Name implements idp.IdentityProvider.Name.
func (idp *identityProvider) Name() string {
	return idp.params.Name
}

// Domain implements idp.IdentityProvider.Domain.
func (idp *identityProvider) Domain() string {
	return idp.params.Domain
}

// Description implements idp.IdentityProvider.Description.
func (idp *identityProvider) Description() string {
	return idp.params.Description
}

// IconURL returns the URL of an icon for the identity provider.
func (idp *identityProvider) IconURL() string {
	return idputil.ServiceURL(idp.initParams.Location, idp.params.Icon)
}

// Interactive implements idp.IdentityProvider.Interactive.
func (*identityProvider) Interactive() bool {
	return true
}

// Hidden implements idp.IdentityProvider.Hidden.
func (idp *identityProvider) Hidden() bool {
	return idp.params.Hidden
}

// Init implements idp.IdentityProvider.Init.
func (idp *identityProvider) Init(_ context.Context, params idp.InitParams) error {
	idp.initParams = params
	return nil
}

// URL implements idp.IdentityProvider.URL.
func (idp *identityProvider) URL(state string) string {
	return idputil.RedirectURL(idp.initParams.URLPrefix, "/login", state)
}

// SetInteraction implements idp.IdentityProvider.SetInteraction.
func (idp *identityProvider) SetInteraction(ierr *httpbakery.Error, dischargeID string) {
}

//  GetGroups implements idp.IdentityProvider.GetGroups.
func (*identityProvider) GetGroups(ctx context.Context, identity *store.Identity) ([]string, error) {
	// TODO(mhilton) store the token in the identity ProviderInfo and
	// retrieve groups on demand rather than on login.
	return identity.ProviderInfo["groups"], nil
}

// Handle implements idp.IdentityProvider.Handle.
func (idp *identityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	var ls idputil.LoginState
	if err := idp.initParams.Codec.Cookie(req, idputil.LoginCookieName, req.Form.Get("state"), &ls); err != nil {
		logger.Infof("Invalid login state: %s", err)
		idputil.BadRequestf(w, "Login failed: invalid login state")
		return
	}

	switch strings.TrimPrefix(req.URL.Path, idp.initParams.URLPrefix) {
	case "/login":
		idpChoice := params.IDPChoiceDetails{
			Domain:      idp.params.Domain,
			Description: idp.params.Description,
			Name:        idp.params.Name,
			URL:         idp.URL(req.Form.Get("state")),
		}
		id, err := idputil.HandleLoginForm(ctx, w, req, idpChoice, idp.initParams.Template, idp.loginUser)
		if err != nil {
			idp.initParams.VisitCompleter.RedirectFailure(ctx, w, req, ls.ReturnTo, ls.State, err)
		}
		if id != nil {
			idp.initParams.VisitCompleter.RedirectSuccess(ctx, w, req, ls.ReturnTo, ls.State, id)
		}
	}
}

func (idp *identityProvider) loginUser(ctx context.Context, username, password string) (*store.Identity, error) {
	return idp.doLogin(ctx, keystone.Auth{
		PasswordCredentials: &keystone.PasswordCredentials{
			Username: username,
			Password: password,
		},
	})
}

// doLogin performs the login with the keystone server.
func (idp *identityProvider) doLogin(ctx context.Context, a keystone.Auth) (*store.Identity, error) {
	resp, err := idp.client.Tokens(ctx, &keystone.TokensRequest{
		Body: keystone.TokensBody{
			Auth: a,
		},
	})
	if err != nil {
		return nil, errgo.WithCausef(err, params.ErrUnauthorized, "cannot log in")
	}
	groups, err := idp.getGroups(ctx, resp.Access.Token.ID)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	user := &store.Identity{
		ProviderID: store.MakeProviderIdentity(idp.Name(), idp.qualifiedName(resp.Access.User.ID)),
		Username:   idp.qualifiedName(resp.Access.User.Username),
		ProviderInfo: map[string][]string{
			"groups": groups,
		},
	}

	if err := idp.initParams.Store.UpdateIdentity(
		ctx,
		user,
		store.Update{
			store.Username:     store.Set,
			store.ProviderInfo: store.Set,
		},
	); err != nil {
		return nil, errgo.Notef(err, "cannot update identity")
	}
	return user, nil
}

// getGroups connects to keystone using token and lists tenants
// associated with the token. The tenants are then converted to groups
// names by suffixing with the domain, if configured.
func (idp *identityProvider) getGroups(ctx context.Context, token string) ([]string, error) {
	resp, err := idp.client.Tenants(ctx, &keystone.TenantsRequest{
		AuthToken: token,
	})
	if err != nil {
		return nil, errgo.Notef(err, "cannot get tenants")
	}
	groups := make([]string, len(resp.Tenants))
	for i, t := range resp.Tenants {
		groups[i] = t.Name
	}
	return groups, nil
}

// doLoginV3 performs the login with the keystone (version 3) server.
func (idp *identityProvider) doLoginV3(ctx context.Context, a keystone.AuthV3) (*store.Identity, error) {
	resp, err := idp.client.AuthTokens(ctx, &keystone.AuthTokensRequest{
		Body: keystone.AuthTokensBody{
			Auth: a,
		},
	})
	if err != nil {
		return nil, errgo.WithCausef(err, params.ErrUnauthorized, "cannot log in")
	}
	groups, err := idp.getGroupsV3(ctx, resp.SubjectToken, resp.Token.User.ID)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	user := &store.Identity{
		ProviderID: store.MakeProviderIdentity(idp.Name(), idp.qualifiedName(resp.Token.User.ID)),
		Username:   idp.qualifiedName(resp.Token.User.Name),
		ProviderInfo: map[string][]string{
			"groups": groups,
		},
	}

	if err := idp.initParams.Store.UpdateIdentity(
		ctx,
		user,
		store.Update{
			store.Username:     store.Set,
			store.ProviderInfo: store.Set,
		},
	); err != nil {
		return nil, errgo.Notef(err, "cannot update identity")
	}
	return user, nil
}

// getGroupsV3 connects to keystone using token and lists groups
// associated with the user. The group names are suffixing with the
// domain, if configured.
func (idp *identityProvider) getGroupsV3(ctx context.Context, token, user string) ([]string, error) {
	resp, err := idp.client.UserGroups(ctx, &keystone.UserGroupsRequest{
		AuthToken: token,
		UserID:    user,
	})
	if err != nil {
		return nil, errgo.Notef(err, "cannot get groups")
	}
	groups := make([]string, len(resp.Groups))
	for i, g := range resp.Groups {
		groups[i] = g.Name
	}
	return groups, nil
}

// qualifiedName returns the given name qualified as appropriate with
// the provider's configured domain.
func (idp *identityProvider) qualifiedName(name string) string {
	if idp.params.Domain != "" {
		return name + "@" + idp.params.Domain
	}
	return name
}
