// Copyright 2015 Canonical Ltd.

package keystone

import (
	"net/http"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
)

// Client provides access to a keystone server. Currently the supported
// protocol is version 2.0, see
// http://developer.openstack.org/api-ref-identity-v2.html for more
// information.
type Client struct {
	client httprequest.Client
}

// NewClient creates a new Client for the keystone server at url.
func NewClient(url string) *Client {
	return &Client{
		client: httprequest.Client{
			BaseURL:        url,
			UnmarshalError: unmarshalError,
		},
	}
}

// Tokens provides access to the /v2.0/tokens endpoint. See
// http://developer.openstack.org/api-ref-identity-v2.html#authenticate-v2.0
// for more information.
func (c *Client) Tokens(r *TokensRequest) (*TokensResponse, error) {
	var resp TokensResponse
	if err := c.client.Call(r, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Tenants provides access to the /v2.0/tenants endpoint. See
// http://developer.openstack.org/api-ref-identity-v2.html#listTenants
// for more information.
func (c *Client) Tenants(r *TenantsRequest) (*TenantsResponse, error) {
	var resp TenantsResponse
	if err := c.client.Call(r, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Error represents an error from a keystone server.
type Error struct {
	Code    int    `json:"code"`
	Title   string `json:"title"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return e.Message
}

// ErrorResponse represents an error response from the keystone server.
type ErrorResponse struct {
	Error *Error `json:"error"`
}

func unmarshalError(r *http.Response) error {
	var jerr ErrorResponse
	if err := httprequest.UnmarshalJSONResponse(r, &jerr); err != nil {
		return err
	}
	if jerr.Error == nil || jerr.Error.Message == "" {
		return errgo.Newf("unsupported error response: %s", r.Status)
	}
	return jerr.Error
}
