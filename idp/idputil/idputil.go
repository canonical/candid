// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package idputil contains utility routines common to many identity
// providers.
package idputil

import (
	"context"
	"html/template"
	"net/http"
	"net/url"

	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
)

var logger = loggo.GetLogger("candid.idp.idputil")

var ReservedUsernames = map[string]bool{
	"admin":    true,
	"everyone": true,
}

// GetLoginMethods uses c to perform a request to get the list of
// available login methods from u. The result is unmarshalled into v.
func GetLoginMethods(ctx context.Context, c *httprequest.Client, u *url.URL, v interface{}) error {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return errgo.Mask(err)
	}
	req.Header.Set("Accept", "application/json")
	if err := c.Do(ctx, req, v); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// RequestParams creates an httprequest.Params object from the given fields.
func RequestParams(ctx context.Context, w http.ResponseWriter, req *http.Request) httprequest.Params {
	return httprequest.Params{
		Response: w,
		Request:  req,
		Context:  ctx,
	}
}

// DischargeID gets the discharge ID from the given request using the
// standard form value.
func DischargeID(req *http.Request) string {
	return req.Form.Get("id")
}

// RedirectParams gets the return_to and state parameters from the
// request.
func RedirectParams(req *http.Request) (returnTo, state string) {
	return req.Form.Get("return_to"), req.Form.Get("state")
}

// URL creates a URL addressed to the given path within the IDP handler
// and adds the given dischargeID (when specified).
func URL(prefix, path, dischargeID string) string {
	callback := prefix + path
	v := make(url.Values)
	if dischargeID != "" {
		v.Set("id", dischargeID)
	}
	if len(v) > 0 {
		callback += "?" + v.Encode()
	}
	return callback
}

type RegistrationParams struct {
	// State contains some opaque state for the registration. It can
	// be used to pass arbitrary data back to the idp once the
	// registration is processed.
	State string

	// Username contains the preferred username for the user. This
	// will be used to populate the username input.
	Username string

	// Error contains an error message if the registration failed.
	Error string

	// Domain contains the domain in which the user is being created.
	// This cannot be modified by the user.
	Domain string

	// FullName contains the full name of the user. This is used to
	// populate the fullname input.
	FullName string

	// Email contains the email address of the user. This is used to
	// populate the email input.
	Email string
}

// RegistrationForm writes a registration form to the given writer using
// the given parameters.
func RegistrationForm(ctx context.Context, w http.ResponseWriter, params RegistrationParams, t *template.Template) error {
	t = t.Lookup("register")
	if t == nil {
		errgo.New("registration template not found")
	}
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	if err := t.Execute(w, params); err != nil {
		return errgo.Notef(err, "cannot process registration template")
	}
	return nil
}

// NameWithDomain builds a name out of name and domain. If domain is
// empty then name is returned unchanged.
func NameWithDomain(name, domain string) string {
	if domain == "" {
		return name
	}
	return name + "@" + domain
}

// RedirectCookieName is the name of the cookie used to store
// RedirectState whilst a login is being processed by a third-party
// server.
const RedirectCookieName = "candid-redirect"

// RedirectState holds the incoming return address and state in a
// redirect based login.
type RedirectState struct {
	ReturnTo string
	State    string
}
