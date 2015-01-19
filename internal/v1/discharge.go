// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"

	"gopkg.in/macaroon-bakery.v0/bakery/checkers"
)

// checkThirdPartyCaveat checks the given caveat. This function is called by the httpbakery
// discharge logic. See httpbakery.AddDischargeHandler for futher details.
func (h *Handler) checkThirdPartyCaveat(req *http.Request, cavId, cav string) ([]checkers.Caveat, error) {
	// TODO (mhilton) Make this function do intelligent checks.
	return []checkers.Caveat{}, nil
}
