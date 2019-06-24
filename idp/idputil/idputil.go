// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package idputil contains utility routines common to many identity
// providers.
package idputil

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/juju/loggo"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"

	"github.com/CanonicalLtd/candid/store"
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

// State gets the state from the given request using the standard form
// value.
func State(req *http.Request) string {
	return req.Form.Get("state")
}

// RedirectURL creates a URL addressed to the given path within the IDP handler
// and adds the given state.
func RedirectURL(prefix, path, state string) string {
	v := url.Values{
		"state": {state},
	}
	return prefix + path + "?" + v.Encode()
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

// LoginCookieName is the name of the cookie used to store LoginState
// whilst a login is being processed.
const LoginCookieName = "candid-login"

// LoginState holds the state of the current loging process.
type LoginState struct {
	// ReturnTo holds the address to return to after the login has
	// completed.
	ReturnTo string

	// State holds an opaque value from the original requesing server
	// that will be sent back to the ReturnTo URL when the login
	// attempt completes.
	State string

	// Expires holds the time that this login attempt should expire.
	Expires time.Time

	// ProvideID holds the ProviderID of an authenticated user. It is
	// only used when the user that has authenticaated requires
	// registration.
	ProviderID store.ProviderIdentity
}

// BadRequestf writes the given bad request message to the given
// ResponseWriter. It should be used by IDPs when they do not have enough
// state to pass the error message along to the initiating page.
func BadRequestf(w http.ResponseWriter, f string, args ...interface{}) {
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, f, args...)
}

// LoginFormParams contains the parameters sent to the login-form
// template.
type LoginFormParams struct {
	params.IDPChoiceDetails

	// Action contains the action parameter for the form.
	Action string

	// Error contains an error message from the previous, failed,
	// login attempt.
	Error string
}
