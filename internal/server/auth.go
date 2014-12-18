// Copyright 2014 Canonical Ltd.

package server

import (
	"net/http"

	"github.com/juju/utils"
)

const authorizationHeader = "Authorization"

// Authorization provides authorization checks for http requests.
type Authorization struct {
	creds string
}

// NewAuthorization creates a new Authorization using the supplied credentials.
func NewAuthorization(params ServerParams) *Authorization {
	return &Authorization{
		creds: utils.BasicAuthHeader(params.AuthUsername, params.AuthPassword).Get(authorizationHeader),
	}
}

// HasAdminCredentials checks if the request has credentials that match the
// configured administration credentials for the server.
func (a Authorization) HasAdminCredentials(req *http.Request) bool {
	return req.Header.Get(authorizationHeader) == a.creds
}
