// Copyright 2015 Canonical Ltd.

// Package test contains an identity provider useful for testing other
// parts of the system. The test identity provider is insecure by design
// so should not be used in any production system.
package test

import (
	"net/http"
	"net/url"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
)

func init() {
	config.RegisterIDP("test", func(func(interface{}) error) (idp.IdentityProvider, error) {
		return IdentityProvider, nil
	})
}

// IdentityProvider is an idp.IdentityProvider that can be used for tests.
var IdentityProvider idp.IdentityProvider = (*identityProvider)(nil)

type identityProvider struct{}

// Name gives the name of the identity provider (test).
func (*identityProvider) Name() string {
	return "test"
}

// Description gives a description of the identity provider.
func (*identityProvider) Description() string {
	return "Test"
}

// Interactive specifies that this identity provider is interactive.
func (*identityProvider) Interactive() bool {
	return true
}

// URL gets the login URL to use this identity provider.
func (*identityProvider) URL(c idp.URLContext, waitID string) (string, error) {
	url := c.URL("/test-login")
	if waitID != "" {
		url += "?waitid=" + waitID
	}
	return url, nil
}

type testInteractiveLoginResponse struct {
	URL string `json:"url"`
}

type testLoginRequest struct {
	httprequest.Route `httprequest:"POST"`
	User              *params.User `httprequest:",body"`
}

// Handle handles the login process.
func (idp *identityProvider) Handle(c idp.Context) {
	p := c.Params()
	switch p.Request.Method {
	case "GET":
		var resp testInteractiveLoginResponse
		var err error
		p.Request.ParseForm()
		resp.URL, err = idp.URL(c, p.Request.Form.Get("waitid"))
		if err != nil {
			c.LoginFailure(err)
			return
		}
		httprequest.WriteJSON(p.Response, http.StatusOK, resp)
	case "POST":
		var req testLoginRequest
		if err := httprequest.Unmarshal(p, &req); err != nil {
			c.LoginFailure(err)
			return
		}
		u := req.User
		if u.ExternalID == "" {
			var err error
			u, err = c.FindUserByName(u.Username)
			if err != nil {
				c.LoginFailure(err)
				return
			}
		} else if u.Username == "" {
			var err error
			u, err = c.FindUserByExternalId(u.ExternalID)
			if err != nil {
				c.LoginFailure(err)
				return
			}
		} else if err := c.UpdateUser(u); err != nil {
			c.LoginFailure(err)
			return
		}
		idputil.LoginUser(c, u)
	default:
		c.LoginFailure(errgo.WithCausef(nil, params.ErrMethodNotAllowed, "%s not allowed", p.Request.Method))
	}
}

type Visitor struct {
	// User contains the user to log in as. User may be fully defined
	// in which case the user is added to the database or can be a
	// Username or ExternalID. If the latter two cases the database
	// will be checked for a matching user.
	User *params.User
}

func (v Visitor) VisitWebPage(client *httpbakery.Client, urls map[string]*url.URL) error {
	cl := &httprequest.Client{
		Doer: client,
	}
	if u, ok := urls["test"]; ok {
		return v.nonInteractive(cl, u)
	}
	return v.interactive(cl, urls[httpbakery.UserInteractionMethod])
}

// Interactive is a web page visit function that performs an interactive
// login.
func (v Visitor) interactive(client *httprequest.Client, u *url.URL) error {
	var resp testInteractiveLoginResponse
	if err := client.Get(u.String(), &resp); err != nil {
		return errgo.Mask(err)
	}
	if err := v.doLogin(client, resp.URL); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// NonInteractive is a web page visit function that performs an
// non-interactive login.
func (v Visitor) nonInteractive(client *httprequest.Client, u *url.URL) error {
	if err := v.doLogin(client, u.String()); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// doLogin performs the common part of the login.
func (v Visitor) doLogin(client *httprequest.Client, url string) error {
	req := &testLoginRequest{
		User: v.User,
	}
	if err := client.CallURL(url, req, nil); err != nil {
		return errgo.Mask(err)
	}
	return nil
}
