// Copyright 2015 Canonical Ltd.

package idmclient

import (
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
}

// New returns a new client.
func New(p NewParams) *Client {
	var c Client
	c.Client.BaseURL = p.BaseURL
	c.Client.Doer = p.Client
	c.Client.UnmarshalError = httprequest.ErrorUnmarshaler(new(params.Error))
	return &c
}

//go:generate httprequest-generate-client github.com/CanonicalLtd/blues-identity/internal/v1 apiHandler client
