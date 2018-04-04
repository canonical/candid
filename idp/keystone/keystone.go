// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package keystone contains identity providers that validate against
// keystone servers.
package keystone

import (
	"html/template"
	"net/http"

	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/idmclient.v1/params"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
	"github.com/CanonicalLtd/blues-identity/idp/keystone/internal/keystone"
	"github.com/CanonicalLtd/blues-identity/store"
)

func init() {
	config.RegisterIDP("keystone", constructor(NewIdentityProvider))
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

	// URL is the address of the keystone server.
	URL string `yaml:"url"`
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

// Interactive implements idp.IdentityProvider.Interactive.
func (*identityProvider) Interactive() bool {
	return true
}

// Init implements idp.IdentityProvider.Init.
func (idp *identityProvider) Init(_ context.Context, params idp.InitParams) error {
	idp.initParams = params
	return nil
}

// URL implements idp.IdentityProvider.URL.
func (idp *identityProvider) URL(dischargeID string) string {
	return idputil.URL(idp.initParams.URLPrefix, "/login", dischargeID)
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
	if req.Form.Get("username") != "" {
		user, err := idp.doLogin(ctx, keystone.Auth{
			PasswordCredentials: &keystone.PasswordCredentials{
				Username: req.Form.Get("username"),
				Password: req.Form.Get("password"),
			},
		})
		if err != nil {
			idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
			return
		}
		idp.initParams.VisitCompleter.Success(ctx, w, req, idputil.DischargeID(req), user)
		return
	}
	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	err := loginTemplate.Execute(w, map[string]string{
		"Description": idp.params.Description,
		"Callback":    idp.URL(idputil.DischargeID(req)),
	})
	if err != nil {
		idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
	}
}

var loginTemplate = template.Must(template.New("").Parse(loginPage))

const loginPage = `<!doctype html>
<html>
	<head><title>{{.Description}} Login</title></head>
	<body>
		<form method="POST" action="{{.Callback}}">
			<p><label>Username: <input type="text" name="username"></label></p>
			<p><label>Password: <input type="password" name="password"></label></p>
			<p><input type="submit"></p>
		</form>
	</body>
</html>
`

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
		groups[i] = idp.qualifiedName(t.Name)
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
		groups[i] = idp.qualifiedName(g.Name)
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
