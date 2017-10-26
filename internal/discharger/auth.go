// Copyright 2017 Canonical Ltd.

package discharger

import (
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/blues-identity/internal/auth"
)

// opForRequest returns the operation that will be performed
// by the API handler method which takes the given argument r.
func opForRequest(_ interface{}) bakery.Op {
	// All of the endpoints are part of the login action and can be
	// accessed by anyone.
	return auth.GlobalOp(auth.ActionLogin)
}
