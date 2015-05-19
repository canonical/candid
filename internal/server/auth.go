// Copyright 2014 Canonical Ltd.

package server

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/juju/utils"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
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

// CheckAdminCredentials checks if the request has credentials that match the
// configured administration credentials for the server. If the credentials match
// nil will be reurned, otherwise the error will describe the failure.
//
// If there are no credentials in the request, it returns params.ErrNoAdminCredsProvided.
func (a Authorizer) CheckAdminCredentials(req *http.Request) error {
	if _, ok := req.Header["Authorization"]; !ok {
		return params.ErrNoAdminCredsProvided
	}
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

// UserHasPublicKeyCaveat creates a first-party caveat that ensures that
// the given user is associated with the given public key.
func UserHasPublicKeyCaveat(user params.Username, pk *bakery.PublicKey) checkers.Caveat {
	return checkers.Caveat{
		Condition: "user-has-public-key " + string(user) + " " + pk.String(),
	}
}

// UserHasPublicKeyChecker is a checker for the "user-has-public-key"
// caveat.
type UserHasPublicKeyChecker struct {
	// Store is used to lookup the specified user id.
	Store *store.Store

	// Identity can be used to save the retrieved identity for
	// later processing. If Identity is not nil then the retrieved
	// identity will be stored there, It is the caller's responsibility
	// to check that this contains the expected identity after
	// processing.
	Identity **mongodoc.Identity
}

// Condition implements checkers.Checker.Condition.
func (UserHasPublicKeyChecker) Condition() string {
	return "user-has-public-key"
}

// Check implements checkers.Checker.Check.
func (c UserHasPublicKeyChecker) Check(_, arg string) error {
	parts := strings.Fields(arg)
	if len(parts) != 2 {
		return errgo.New("caveat badly formatted")
	}
	var username params.Username
	err := username.UnmarshalText([]byte(parts[0]))
	if err != nil {
		return errgo.Mask(err)
	}
	var publicKey bakery.PublicKey
	err = publicKey.UnmarshalText([]byte(parts[1]))
	if err != nil {
		return errgo.Notef(err, "invalid public key %q", parts[1])
	}
	id, err := c.Store.GetIdentity(username)
	if err != nil {
		if errgo.Cause(err) != params.ErrNotFound {
			return errgo.Mask(err)
		}
		return errgo.Newf("public key not valid for user")
	}
	for _, pk := range id.PublicKeys {
		if !bytes.Equal(pk.Key, publicKey.Key[:]) {
			continue
		}
		if c.Identity != nil {
			*c.Identity = id
		}
		return nil
	}
	return errgo.Newf("public key not valid for user")
}
