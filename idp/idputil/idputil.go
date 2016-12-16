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
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/idp"
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
	if c.LoginSuccess(params.Username(u.Username), time.Now().Add(identityMacaroonDuration)) {
		fmt.Fprintf(c.Params().Response, "login successful as user %s\n", u.Username)
	}
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
