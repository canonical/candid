// Copyright 2015 Canonical Ltd.

// Package idputil contains utility routines common to many identity
// providers.
package idputil

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"

	"github.com/CanonicalLtd/blues-identity/idp"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
)

const (
	// identityMacaroonDuration is the length of time for which an
	// identity macaroon is valid.
	identityMacaroonDuration = 28 * 24 * time.Hour
)

// LoginUser completes a successful login for the specified user. A new
// identity macaroon is generated for the user and an appropriate message
// will be returned for the login request.
func LoginUser(c idp.Context, u *params.User) {
	t := time.Now()
	u.LastLogin = &t
	if err := c.UpdateUser(u); err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot update last login time"))
	}
	m, err := CreateMacaroon(c.Bakery(), string(u.Username), identityMacaroonDuration, c.Params().Request)
	if err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot create macaroon"))
		return
	}
	if c.LoginSuccess(macaroon.Slice{m}) {
		fmt.Fprintf(c.Params().Response, "login successful as user %s\n", u.Username)
	}
}

// GetLoginMethods uses c to perform a request to get the list of
// available login methods from u. The result is unmarshalled into v.
func GetLoginMethods(c *httprequest.Client, u *url.URL, v interface{}) error {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return errgo.Mask(err)
	}
	req.Header.Set("Accept", "application/json")
	if err := c.Do(req, nil, v); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// CreateMacaroon generates a new identity macaroon for the user provided
// with a version appropriate for the client that sent the given request.
func CreateMacaroon(service *bakery.Service, username string, duration time.Duration, req *http.Request) (*macaroon.Macaroon, error) {
	return service.NewMacaroon(httpbakery.RequestVersion(req), []checkers.Caveat{
		checkers.DeclaredCaveat("username", username),
		checkers.TimeBeforeCaveat(time.Now().Add(duration)),
	})
}
