// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"
	"time"

	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v0/bakery/checkers"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

// checkThirdPartyCaveat checks the given caveat. This function is called by the httpbakery
// discharge logic. See httpbakery.AddDischargeHandler for futher details.
func (h *Handler) checkThirdPartyCaveat(req *http.Request, cavId, cav string) ([]checkers.Caveat, error) {
	switch cav {
	case "is-authenticated-user":
		return h.checkAuthenticatedUser(req)
	default:
		return nil, checkers.ErrCaveatNotRecognized
	}
}

// checkAuthenticatedUser checks a third-party caveat for "is-authenticated-user". Currently the discharge
// macaroon will only be created for users with admin credentials.
func (h *Handler) checkAuthenticatedUser(req *http.Request) ([]checkers.Caveat, error) {
	// TODO(mhilton) check for an identity macaroon cookie in the request.
	if err := h.auth.CheckAdminCredentials(req); err != nil {
		return nil, errgo.WithCausef(err, params.ErrUnauthorized, "")
	}
	req.ParseForm()
	name := req.Form.Get("discharge-for-user")
	if name == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "username not specified")
	}
	var user mongodoc.Identity
	if err := h.store.DB.Identities().Find(bson.M{"username": name}).One(&user); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return nil, errgo.WithCausef(err, params.ErrForbidden, "user %q not found", name)
		}
	}
	return []checkers.Caveat{
		checkers.DeclaredCaveat("uuid", user.UUID),
		checkers.DeclaredCaveat("username", user.UserName),
		checkers.TimeBeforeCaveat(time.Now().Add(24 * time.Hour)),
	}, nil
}
