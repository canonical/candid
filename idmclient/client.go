// Copyright 2015 Canonical Ltd.

package idmclient

import (
	"io"
	"net/http"

	"github.com/juju/httprequest"
	"gopkg.in/macaroon-bakery.v1/httpbakery"

	"github.com/CanonicalLtd/blues-identity/params"
)

const (
	Production = "https://api.jujucharms.com/identity"
	Staging    = "https://api.staging.jujucharms.com/identity"
)

// Client represents the client of an identity server.
type Client struct {
	client
}

// NewParams holds the parameters for creating a new client.
type NewParams struct {
	BaseURL string
	Client  *httpbakery.Client

	// AuthUsername holds the username for admin login.
	AuthUsername string

	// AuthPassword holds the password for admin login.
	AuthPassword string
}

// New returns a new client.
func New(p NewParams) *Client {
	var c Client
	c.Client.BaseURL = p.BaseURL
	if p.AuthUsername != "" {
		c.Client.Doer = &basicAuthClient{
			client:   p.Client,
			user:     p.AuthUsername,
			password: p.AuthPassword,
		}
	} else {
		c.Client.Doer = p.Client
	}
	c.Client.UnmarshalError = httprequest.ErrorUnmarshaler(new(params.Error))
	return &c
}

// basicAuthClient wraps a bakery.Client, adding a basic auth
// header to every request.
type basicAuthClient struct {
	client   *httpbakery.Client
	user     string
	password string
}

func (c *basicAuthClient) Do(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(c.user, c.password)
	return c.client.Do(req)
}

func (c *basicAuthClient) DoWithBody(req *http.Request, r io.ReadSeeker) (*http.Response, error) {
	req.SetBasicAuth(c.user, c.password)
	return c.client.DoWithBody(req, r)
}

//go:generate httprequest-generate-client github.com/CanonicalLtd/blues-identity/internal/v1 apiHandler client
