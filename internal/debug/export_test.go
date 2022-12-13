// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package debug

import "github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"

type (
	DebugAPIHandler *debugAPIHandler
	Cookie          cookie
)

var (
	New = newDebugAPIHandler
)

// DecodeCookie is a wrapper around decodeCookie that can be used for
// testing.
func DecodeCookie(k *bakery.KeyPair, s string) (*Cookie, error) {
	c, err := decodeCookie(k, s)
	return (*Cookie)(c), err
}

// EncodeCookie is a wrapper around encodeCookie that can be used for
// testing.
func EncodeCookie(k *bakery.KeyPair, c *Cookie) (string, error) {
	return encodeCookie(k, (*cookie)(c))
}
