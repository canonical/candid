// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package internal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/juju/simplekv"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/candid/store"
)

// DischargeTokenStore is a store for discharge tokens. It wraps a
// KeyValueStore.
type DischargeTokenStore struct {
	store simplekv.Store
}

// NewDischargeTokenStore creates a new DischargeTokenStore using the
// given KeyValueStore for backing storage.
func NewDischargeTokenStore(store simplekv.Store) *DischargeTokenStore {
	return &DischargeTokenStore{store: store}
}

// Put adds the given DischargeToken to the store, returning the key that
// should be used to later retrieve the token. The DischargeToken will
// only be available in the store until the given expire time.
func (s *DischargeTokenStore) Put(ctx context.Context, dt *httpbakery.DischargeToken, expire time.Time) (string, error) {
	entry := dischargeTokenEntry{
		DischargeToken: dt,
		Expire:         expire,
	}
	b, err := json.Marshal(entry)
	if err != nil {
		// This should be impossible.
		panic(err)
	}
	hash := sha256.Sum256(b)
	key := base64.RawURLEncoding.EncodeToString(hash[:])
	if err := s.store.Set(ctx, key, b, expire); err != nil {
		return "", errgo.Mask(err, errgo.Is(context.Canceled), errgo.Is(context.DeadlineExceeded))
	}
	return key, nil
}

// Get retrieves the DischargeToken with the given key from the store. If
// there is no such token, or the token has expired, then the returned
// error will have a cause of store.ErrNotFound.
func (s *DischargeTokenStore) Get(ctx context.Context, key string) (*httpbakery.DischargeToken, error) {
	b, err := s.store.Get(ctx, key)
	if err != nil {
		if errgo.Cause(err) == simplekv.ErrNotFound {
			return nil, errgo.WithCausef(err, store.ErrNotFound, "")
		}
		return nil, errgo.Mask(err, errgo.Is(context.Canceled), errgo.Is(context.DeadlineExceeded))
	}
	var entry dischargeTokenEntry
	if err := json.Unmarshal(b, &entry); err != nil {
		return nil, errgo.Mask(err)
	}
	if entry.Expire.Before(time.Now()) {
		return nil, errgo.WithCausef(nil, store.ErrNotFound, "%q not found", key)
	}
	return entry.DischargeToken, nil
}

type dischargeTokenEntry struct {
	DischargeToken *httpbakery.DischargeToken
	Expire         time.Time
}
