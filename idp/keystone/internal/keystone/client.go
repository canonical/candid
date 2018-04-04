// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone

import (
	"net/http"

	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
)

const subjectTokenHeader = "X-Subject-Token"

// Client provides access to a keystone server. Currently the supported
// protocols are versions 2.0 & 3, see
// http://developer.openstack.org/api-ref-identity-v2.html or
// http://developer.openstack.org/api-ref/identity/v3/index.html for more
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
func (c *Client) Tokens(ctx context.Context, r *TokensRequest) (*TokensResponse, error) {
	var resp TokensResponse
	if err := c.client.Call(ctx, r, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Tenants provides access to the /v2.0/tenants endpoint. See
// http://developer.openstack.org/api-ref-identity-v2.html#listTenants
// for more information.
func (c *Client) Tenants(ctx context.Context, r *TenantsRequest) (*TenantsResponse, error) {
	var resp TenantsResponse
	if err := c.client.Call(ctx, r, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AuthTokens provides access to the /v3/auth/tokens endpoint. See
// http://developer.openstack.org/api-ref/identity/v3/index.html?expanded=password-authentication-with-unscoped-authorization-detail
// for more information. This uses version 3 of the keystone protocol and
// therefore cannot be used with older keystone servers that don't
// support it.
func (c *Client) AuthTokens(ctx context.Context, r *AuthTokensRequest) (*AuthTokensResponse, error) {
	// Initially get the whole http.Response so that we can read the
	// "X-Subject-Token" header.
	var resp *http.Response
	if err := c.client.Call(ctx, r, &resp); err != nil {
		return nil, err
	}
	var authResp AuthTokensResponse
	if err := httprequest.UnmarshalJSONResponse(resp, &authResp); err != nil {
		return nil, err
	}
	authResp.SubjectToken = resp.Header.Get(subjectTokenHeader)
	return &authResp, nil
}

// UserGroups provides access to the /v3/users/:id/groups endpoint. See
// http://developer.openstack.org/api-ref/identity/v3/index.html?expanded=list-groups-to-which-a-user-belongs-detail
// for more information. This uses version 3 of the keystone protocol and
// therefore cannot be used with older keystone servers that don't
// support it.
func (c *Client) UserGroups(ctx context.Context, r *UserGroupsRequest) (*UserGroupsResponse, error) {
	var resp UserGroupsResponse
	if err := c.client.Call(ctx, r, &resp); err != nil {
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
