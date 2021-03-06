// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package idptest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"

	errgo "gopkg.in/errgo.v1"

	"github.com/canonical/candid/v2/idp"
	"github.com/canonical/candid/v2/idp/idputil"
	"github.com/canonical/candid/v2/idp/idputil/secret"
)

// A Client allows tests to simulate sending HTTP requests to an IDP.
type Client struct {
	idp        idp.IdentityProvider
	codec      *secret.Codec
	loginState *http.Cookie
	state      string
}

// NewClient create a new client for the given IDP.
func NewClient(idp idp.IdentityProvider, codec *secret.Codec) *Client {
	return &Client{
		idp:   idp,
		codec: codec,
	}
}

// SetLoginStatus sets a login status that will be added to every
// request.
func (c *Client) SetLoginState(state idputil.LoginState) {
	value, err := c.codec.Encode(state)
	if err != nil {
		panic(err)
	}
	c.loginState = &http.Cookie{
		Name:  idputil.LoginCookieName,
		Value: value,
	}
	rawValue, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(rawValue)
	c.state = base64.RawURLEncoding.EncodeToString(hash[:])
}

// Do simulates a round trip to the idp handler.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c.loginState != nil {
		v := req.URL.Query()
		v.Set("state", c.state)
		req.URL.RawQuery = v.Encode()
		req.AddCookie(c.loginState)
	}
	req.ParseForm()
	w := httptest.NewRecorder()
	c.idp.Handle(context.Background(), w, req)
	return w.Result(), nil
}

// Get simulates a get request on the idp handler.
func (c *Client) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return c.Do(req)
}
