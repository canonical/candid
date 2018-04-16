// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone

import (
	"net/http"
	"strings"

	"github.com/juju/schema"
	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/errgo.v1"
	gooseidentity "gopkg.in/goose.v1/identity"
	"gopkg.in/httprequest.v1"
	"gopkg.in/juju/environschema.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/form"

	"github.com/CanonicalLtd/candid/config"
	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idputil"
	"github.com/CanonicalLtd/candid/idp/keystone/internal/keystone"
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

// SetInteraction implements idp.IdentityProvider.SetInteraction.
func (idp *userpassIdentityProvider) SetInteraction(ierr *httpbakery.Error, dischargeID string) {
	ierr.SetInteraction(form.InteractionMethod, form.InteractionInfo{
		URL: idputil.URL(idp.initParams.URLPrefix, "/interact", dischargeID),
	})
}

// Handle implements idp.IdentityProvider.Handle.
func (idp *userpassIdentityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		httprequest.WriteJSON(w, http.StatusOK, keystoneSchemaResponse)
		return
	}
	var lr form.LoginRequest
	if err := httprequest.Unmarshal(idputil.RequestParams(ctx, w, req), &lr); err != nil {
		idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), errgo.WithCausef(err, params.ErrBadRequest, "cannot unmarshal login request"))
		return
	}
	frm, err := keystoneFieldsChecker.Coerce(lr.Body.Form, nil)
	if err != nil {
		idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), errgo.Notef(err, "cannot validate form"))
		return
	}
	m := frm.(map[string]interface{})
	user, err := idp.doLogin(ctx, keystone.Auth{
		PasswordCredentials: &keystone.PasswordCredentials{
			Username: m["username"].(string),
			Password: m["password"].(string),
		},
	})
	if err != nil {
		idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), errgo.Notef(err, "cannot validate form"))
		return
	}
	if strings.TrimPrefix(req.URL.Path, idp.initParams.URLPrefix) == "/interact" {
		dt, err := idp.initParams.DischargeTokenCreator.DischargeToken(ctx, user)
		if err != nil {
			idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
			return
		}
		httprequest.WriteJSON(w, http.StatusOK, form.LoginResponse{
			Token: dt,
		})
	} else {
		idp.initParams.VisitCompleter.Success(ctx, w, req, idputil.DischargeID(req), user)
	}
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
