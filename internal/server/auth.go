// Copyright 2014 Canonical Ltd.

package server

import (
	"net/http"

	"github.com/juju/utils"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/params"
)

// Authorizer provides authorization checks for http requests.
type Authorizer struct {
	username string
	password string
}

// NewAuthorizer creates a new Authorizer using the supplied credentials.
func NewAuthorizer(params ServerParams) *Authorizer {
	return &Authorizer{
		username: params.AuthUsername,
		password: params.AuthPassword,
	}
}

// HasAdminCredentials checks if the request has credentials that match the
// configured administration credentials for the server. If the credentials match
// nil will be reurned, otherwise the error will describe the failure.
func (a Authorizer) HasAdminCredentials(req *http.Request) error {
	u, p, err := utils.ParseBasicAuthHeader(req.Header)
	if err != nil {
		return errgo.WithCausef(err, params.ErrUnauthorized, "")
	}
	if u != a.username {
		return errgo.WithCausef(nil, params.ErrUnauthorized, "invalid credentials")
	}
	if p != a.password {
		return errgo.WithCausef(nil, params.ErrUnauthorized, "invalid credentials")
	}
	return nil
}
