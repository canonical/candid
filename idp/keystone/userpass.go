// Copyright 2015 Canonical Ltd.

package keystone

import (
	"net/http"

	"github.com/juju/httprequest"
	"github.com/juju/schema"
	"gopkg.in/errgo.v1"
	gooseidentity "gopkg.in/goose.v1/identity"
	"gopkg.in/juju/environschema.v1"
	"gopkg.in/macaroon-bakery.v1/httpbakery/form"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/keystone/internal/keystone"
	"github.com/CanonicalLtd/blues-identity/params"
)

func init() {
	config.RegisterIDP("keystone_userpass", constructor(NewUserpassIdentityProvider))
}

// NewTokenIdentityProvider creates a idp.IdentityProvider which will
// authenticate against a keystone server using a httpbakery.form
// compatible login method.
func NewUserpassIdentityProvider(p Params) idp.IdentityProvider {
	return &userpassIdentityProvider{
		identityProvider: newIdentityProvider(p),
	}
}

// userpassIdentityProvider is an identity provider that uses a
// configured keystone instance to authenticate against using
// httpbakery.form to pass login parameters.
type userpassIdentityProvider struct {
	identityProvider
}

// Interactive implements idp.IdentityProvider.Interactive.
func (*userpassIdentityProvider) Interactive() bool {
	return false
}

// Handle implements idp.IdentityProvider.Handle.
func (idp *userpassIdentityProvider) Handle(c idp.Context) {
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
