// Copyright 2015 Canonical Ltd.

package idp

import (
	"html/template"
	"net/http"

	"github.com/juju/httprequest"
	"github.com/juju/schema"
	"gopkg.in/errgo.v1"
	gooseidentity "gopkg.in/goose.v1/identity"
	"gopkg.in/juju/environschema.v1"
	"gopkg.in/macaroon-bakery.v1/httpbakery/form"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/keystone"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

// KeystoneIdentityProvider is an identity provider that uses a
// configured keystone instance to authenticate against.
type KeystoneIdentityProvider struct {
	params idp.KeystoneParams
	client *keystone.Client
}

// NewKeystoneIdentityProvider creates a KeystoneIdentityProvider with
// the given configuration.
func NewKeystoneIdentityProvider(p *idp.KeystoneParams) *KeystoneIdentityProvider {
	idp := KeystoneIdentityProvider{
		params: *p,
		client: keystone.NewClient(p.URL),
	}
	if idp.params.Description == "" {
		idp.params.Description = idp.params.Name
	}
	return &idp
}

func (idp *KeystoneIdentityProvider) Name() string {
	return idp.params.Name
}

func (idp *KeystoneIdentityProvider) Description() string {
	return idp.params.Description
}

func (*KeystoneIdentityProvider) Interactive() bool {
	return true
}

func (*KeystoneIdentityProvider) URL(c Context, waitID string) (string, error) {
	url := c.IDPURL("/login")
	if waitID != "" {
		url += "?waitid=" + waitID
	}
	return url, nil
}

func (idp *KeystoneIdentityProvider) Handle(c Context) {
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
	url := c.IDPURL("/login")
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

func (idp *KeystoneIdentityProvider) doLogin(c Context, a keystone.Auth) {
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
	identity := mongodoc.Identity{
		Username:   idp.qualifiedName(resp.Access.User.Username),
		ExternalID: idp.qualifiedName(resp.Access.User.ID),
		Groups:     groups,
	}
	if err := c.Store().UpsertIdentity(&identity); err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot update identity"))
		return
	}
	loginIdentity(c, &identity)
}

// getGroups connects to keystone using token and lists tenants
// associated with the token. The tenants are then converted to groups
// names by suffixing with the domain, if configured.
func (idp *KeystoneIdentityProvider) getGroups(token string) ([]string, error) {
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
func (idp *KeystoneIdentityProvider) qualifiedName(name string) string {
	if idp.params.Domain != "" {
		return name + "@" + idp.params.Domain
	}
	return name
}

// KeystoneUserpassIdentityProvider is an IdentityProvider with identical
// behaviour to the KeystoneIdentityProvider except that it is not
// interactive.
type KeystoneUserpassIdentityProvider struct {
	KeystoneIdentityProvider
}

// NewKeystoneUserpassIdentityProvider creates a
// KeystoneUserpassIdentityProvider with the given configuration.
func NewKeystoneUserpassIdentityProvider(p *idp.KeystoneParams) *KeystoneUserpassIdentityProvider {
	return &KeystoneUserpassIdentityProvider{
		KeystoneIdentityProvider: *NewKeystoneIdentityProvider(p),
	}
}

func (*KeystoneUserpassIdentityProvider) Interactive() bool {
	return false
}

func (idp *KeystoneUserpassIdentityProvider) Handle(c Context) {
	p := c.Params()
	if p.Request.Method != "POST" {
		httprequest.WriteJSON(p.Response, http.StatusOK, keystoneSchemaResponse)
		return
	}
	var lr form.LoginRequest
	if err := httprequest.Unmarshal(p, &lr); err != nil {
		c.LoginFailure(errgo.WithCausef(err, params.ErrBadRequest, "cannot unmarshal login request"))
		return
	}
	form, err := keystoneFieldsChecker.Coerce(lr.Body.Form, nil)
	if err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot validate form"))
		return
	}
	m := form.(map[string]interface{})
	idp.doLogin(c, keystone.Auth{
		PasswordCredentials: &keystone.PasswordCredentials{
			Username: m["username"].(string),
			Password: m["password"].(string),
		},
	})
}

var keystoneSchemaResponse = form.SchemaResponse{
	Schema: keystoneFields,
}

var keystoneFields = environschema.Fields{
	"username": environschema.Attr{
		Description: "username",
		Type:        environschema.Tstring,
		Mandatory:   true,
		EnvVars:     gooseidentity.CredEnvUser,
	},
	"password": environschema.Attr{
		Description: "password",
		Type:        environschema.Tstring,
		Mandatory:   true,
		Secret:      true,
		EnvVars:     gooseidentity.CredEnvSecrets,
	},
}

var keystoneFieldsChecker = schema.FieldMap(mustValidationSchema(keystoneFields))

func mustValidationSchema(fields environschema.Fields) (schema.Fields, schema.Defaults) {
	f, d, err := fields.ValidationSchema()
	if err != nil {
		panic(err)
	}
	return f, d
}

// KeystoneTokenIdentityProvider is an identity provider that uses a
// configured keystone instance to authenticate against using an existing
// token to authenticate.
type KeystoneTokenIdentityProvider struct {
	KeystoneIdentityProvider
}

// NewKeystoneTokenIdentityProvider creates a KeystoneTokenIdentityProvider with
// the given configuration.
func NewKeystoneTokenIdentityProvider(p *idp.KeystoneParams) *KeystoneTokenIdentityProvider {
	return &KeystoneTokenIdentityProvider{
		KeystoneIdentityProvider: *NewKeystoneIdentityProvider(p),
	}
}

func (*KeystoneTokenIdentityProvider) Interactive() bool {
	return false
}

func (idp *KeystoneTokenIdentityProvider) Handle(c Context) {
	var lr keystoneTokenLoginRequest
	if err := httprequest.Unmarshal(c.Params(), &lr); err != nil {
		c.LoginFailure(errgo.WithCausef(err, params.ErrBadRequest, "cannot unmarshal login request"))
		return
	}
	idp.doLogin(c, keystone.Auth{
		Token: &keystone.Token{
			ID: lr.Token.Login.ID,
		},
	})
}

type keystoneTokenLoginRequest struct {
	httprequest.Route `httprequest:"POST"`
	Token             keystoneToken `httprequest:",body"`
}

type idName struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// keystoneToken is the token sent to use to login to the keystone
// server. The only part that is used is Login.ID.
type keystoneToken struct {
	Login struct {
		Domain idName `json:"domain"`
		User   idName `json:"user"`
		Tenant idName `json:"tenant"`
		ID     string `json:"id"`
	} `json:"login"`
}

type keystoneTokenAuthenticationRequest struct {
	Auth keystoneTokenAuth `json:"auth"`
}

type keystoneTokenAuth struct {
	Token      keystoneTokenToken `json:"token"`
	TenantName string             `json:"tenantName"`
}

type keystoneTokenToken struct {
	ID string `json:"id"`
}
