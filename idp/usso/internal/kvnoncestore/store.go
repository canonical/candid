// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package kvnoncestore is an openid.NonceStore that is backed by a store.KeyValueStore.
package kvnoncestore

import (
	"fmt"
	"time"

	"github.com/juju/loggo"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/store"
)

var logger = loggo.GetLogger("idp.usso.internal.kvnoncestore")

// Store is an openid.NonceStore that is backed by a store.KeyValueStore.
type Store struct {
	store  store.KeyValueStore
	maxAge time.Duration
}

// New creates a new Store.
func New(store store.KeyValueStore, maxAge time.Duration) *Store {
	return &Store{
		store:  store,
		maxAge: maxAge,
	}
}

// Accept implements openid.NonceStore.Accept.
func (s *Store) Accept(endpoint, nonce string) error {
	return s.accept(endpoint, nonce, time.Now())
}

// accept is the implementation of Accept. The third parameter is the
// current time, useful for testing.
func (s *Store) accept(endpoint, nonce string, now time.Time) error {
	// From the openid specification:
	//
	// openid.response_nonce
	//
	// Value: A string 255 characters or less in length, that MUST be
	// unique to this particular successful authentication response.
	// The nonce MUST start with the current time on the server, and
	// MAY contain additional ASCII characters in the range 33-126
	// inclusive (printable non-whitespace characters), as necessary
	// to make each response unique. The date and time MUST be
	// formatted as specified in section 5.6 of [RFC3339], with the
	// following restrictions:
	//
	// + All times must be in the UTC timezone, indicated with a "Z".
	//
	// + No fractional seconds are allowed
	//
	// For example: 2005-05-15T17:11:51ZUNIQUE

	if len(nonce) < 20 {
		return errgo.Newf("%q does not contain a valid timestamp", nonce)
	}
	t, err := time.Parse(time.RFC3339, nonce[:20])
	if err != nil {
		return errgo.Notef(err, "%q does not contain a valid timestamp", nonce)
	}
	if t.Before(now.Add(-s.maxAge)) {
		return errgo.Newf("%q too old", nonce)
	}
	key := fmt.Sprintf("nonce#%s#%s", endpoint, nonce)
	err = s.store.Add(context.Background(), key, nil, t.Add(s.maxAge))
	if errgo.Cause(err) == store.ErrDuplicateKey {
		return errgo.Newf("%q already seen for %q", nonce, endpoint)
	}
	return errgo.Mask(err)
}
