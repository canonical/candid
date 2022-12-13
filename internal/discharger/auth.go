// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"

	"github.com/canonical/candid/internal/auth"
)

// opForRequest returns the operation that will be performed
// by the API handler method which takes the given argument r.
func opForRequest(_ interface{}) bakery.Op {
	// All of the endpoints are part of the login action and can be
	// accessed by anyone.
	return auth.GlobalOp(auth.ActionLogin)
}
