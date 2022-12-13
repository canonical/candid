// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package auth

import (
	"bytes"
	"context"
	"strings"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery/checkers"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery"
	"gopkg.in/errgo.v1"

	"github.com/canonical/candid/params"
	"github.com/canonical/candid/store"
)

const (
	checkersNamespace         = "jujucharms.com/identity"
	userHasPublicKeyCondition = "user-has-public-key"
)

// Namespace contains the checkers.Namespace supported by the identity
// service.
var Namespace = checkers.NewNamespace(map[string]string{
	checkers.StdNamespace:        "",
	httpbakery.CheckersNamespace: "http",
	checkersNamespace:            "",
})

func NewChecker(a *Authorizer) *checkers.Checker {
	checker := httpbakery.NewChecker()
	checker.Namespace().Register(checkersNamespace, "")
	checker.Register(userHasPublicKeyCondition, checkersNamespace, a.checkUserHasPublicKey)
	return checker
}

// UserHasPublicKeyCaveat creates a first-party caveat that ensures that
// the given user is associated with the given public key.
func UserHasPublicKeyCaveat(user params.Username, pk *bakery.PublicKey) checkers.Caveat {
	return checkers.Caveat{
		Namespace: checkersNamespace,
		Condition: checkers.Condition(userHasPublicKeyCondition, string(user)+" "+pk.String()),
	}
}

// checkUserHasPublicKey checks the "user-has-public-key" caveat.
func (a *Authorizer) checkUserHasPublicKey(ctx context.Context, cond, arg string) error {
	parts := strings.Fields(arg)
	if len(parts) != 2 {
		return errgo.New("caveat badly formatted")
	}
	var publicKey bakery.PublicKey
	if err := publicKey.UnmarshalText([]byte(parts[1])); err != nil {
		return errgo.Notef(err, "invalid public key %q", parts[1])
	}
	identity := store.Identity{
		Username: parts[0],
	}
	if err := a.store.Identity(ctx, &identity); err != nil {
		if errgo.Cause(err) != store.ErrNotFound {
			return errgo.Mask(err)
		}
		return errgo.Newf("public key not valid for user")
	}
	for _, pk := range identity.PublicKeys {
		if bytes.Equal(pk.Key[:], publicKey.Key[:]) {
			return nil
		}
	}
	return errgo.Newf("public key not valid for user")
}
