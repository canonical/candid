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

// WebPageVisitor implements the login protocol required for the test
// identity provider.
type WebPageVisitor struct {
	// Client is a client to use for the login.
	Client *httprequest.Client

	// User contains the user to log in as. User may be fully defined
	// in which case the user is added to the database or can be a
	// Username or ExternalID. If the latter two cases the database
	// will be checked for a matching user.
	User *params.User
}

// Interactive is a web page visit function that performs an interactive
// login.
func (v WebPageVisitor) Interactive(u *url.URL) error {
	var resp testInteractiveLoginResponse
	if err := v.Client.Get(u.String(), &resp); err != nil {
		return errgo.Mask(err)
	}
	if err := v.doLogin(resp.URL); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

type testLoginMethods struct {
	Test string `json:"test"`
}

// NonInteractive is a web page visit function that performs an
// non-interactive login.
func (v WebPageVisitor) NonInteractive(u *url.URL) error {
	var lm testLoginMethods
	if err := idputil.GetLoginMethods(v.Client, u, &lm); err != nil {
		return errgo.Mask(err)
	}
	if err := v.doLogin(lm.Test); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// doLogin performs the common part of the login.
func (v WebPageVisitor) doLogin(url string) error {
	req := &testLoginRequest{
		User: v.User,
	}
	if err := v.Client.CallURL(url, req, nil); err != nil {
		return errgo.Mask(err)
	}
	return nil
}
