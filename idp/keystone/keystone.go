// Copyright 2015 Canonical Ltd.

// Package keystone contains identity providers that validate against
// keystone servers.
package keystone

import (
	"html/template"

	"github.com/juju/idmclient/params"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
	"github.com/CanonicalLtd/blues-identity/idp/keystone/internal/keystone"
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
	params Params
	client *keystone.Client
}

// Name implements idp.IdentityProvider.Name.
func (idp *identityProvider) Name() string {
	return idp.params.Name
}

// Description implements idp.IdentityProvider.Description.
func (idp *identityProvider) Description() string {
	return idp.params.Description
}

// Interactive implements idp.IdentityProvider.Interactive.
func (*identityProvider) Interactive() bool {
	return true
}

// URL implements idp.IdentityProvider.URL.
func (*identityProvider) URL(c idp.URLContext, waitID string) (string, error) {
	url := c.URL("/login")
	if waitID != "" {
		url += "?waitid=" + waitID
	}
	return url, nil
}

// Handle implements idp.IdentityProvider.Handle.
func (idp *identityProvider) Handle(c idp.Context) {
	p := c.Params()
	p.Request.ParseForm()
	if p.Request.Form.Get("username") != "" {
		idp.doLogin(c, keystone.Auth{
			PasswordCredentials: &keystone.PasswordCredentials{
				Username: p.Request.Form.Get("username"),
				Password: p.Request.Form.Get("password"),
			},
		})
		return
	}
	url := c.URL("/login")
	if p.Request.Form.Get("waitid") != "" {
		url += "?waitid=" + p.Request.Form.Get("waitid")
	}
	p.Response.Header().Set("Content-Type", "text/html;charset=UTF-8")
	err := loginTemplate.Execute(p.Response, map[string]string{
		"Description": idp.params.Description,
		"Callback":    url,
	})
	if err != nil {
		c.LoginFailure(err)
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

// doLogin preforms the login with the keystone server.
func (idp *identityProvider) doLogin(c idp.Context, a keystone.Auth) {
	resp, err := idp.client.Tokens(&keystone.TokensRequest{
		Body: keystone.TokensBody{
			Auth: a,
		},
	})
	if err != nil {
		c.LoginFailure(errgo.WithCausef(err, params.ErrUnauthorized, "cannot log in"))
		return
	}
	groups, err := idp.getGroups(resp.Access.Token.ID)
	if err != nil {
		c.LoginFailure(errgo.Mask(err))
		return
	}
	user := &params.User{
		Username:   params.Username(idp.qualifiedName(resp.Access.User.Username)),
		ExternalID: idp.qualifiedName(resp.Access.User.ID),
		IDPGroups:  groups,
	}

	if err := c.UpdateUser(user); err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot update identity"))
		return
	}
	idputil.LoginUser(c, user)
}

// getGroups connects to keystone using token and lists tenants
// associated with the token. The tenants are then converted to groups
// names by suffixing with the domain, if configured.
func (idp *identityProvider) getGroups(token string) ([]string, error) {
	resp, err := idp.client.Tenants(&keystone.TenantsRequest{
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

// qualifiedName returns the given name qualified as appropriate with
// the provider's configured domain.
func (idp *identityProvider) qualifiedName(name string) string {
	if idp.params.Domain != "" {
		return name + "@" + idp.params.Domain
	}
	return name
}
