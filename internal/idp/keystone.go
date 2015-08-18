// Copyright 2015 Canonical Ltd.

package idp

import (
	"html/template"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/goose.v1/identity"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

type KeystoneIdentityProvider struct {
	params idp.KeystoneParams
	auth   identity.Authenticator
}

func NewKeystoneIdentityProvider(p *idp.KeystoneParams) *KeystoneIdentityProvider {
	idp := KeystoneIdentityProvider{
		params: *p,
		auth:   identity.NewAuthenticator(identity.AuthUserPass, nil),
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
		idp.doLogin(c, p)
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

func (idp *KeystoneIdentityProvider) doLogin(c Context, p httprequest.Params) {
	name := p.Request.Form.Get("username")
	ad, err := idp.auth.Auth(&identity.Credentials{
		URL:     idp.params.URL + "/tokens",
		User:    name,
		Secrets: p.Request.Form.Get("password"),
	})
	if err != nil {
		c.LoginFailure(errgo.WithCausef(err, params.ErrUnauthorized, "cannot log in"))
		return
	}
	externalID := ad.UserId
	if idp.params.Domain != "" {
		name += "@" + idp.params.Domain
		externalID += "@" + idp.params.Domain
	}
	identity := mongodoc.Identity{
		Username:   name,
		ExternalID: externalID,
	}
	if err := c.Store().UpsertIdentity(&identity); err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot update identity"))
		return
	}
	loginIdentity(c, &identity)
}
