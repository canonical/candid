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

	"github.com/canonical/candid/v2/store"
)

// IdentityStore is a short-term store for identity information
// associated with a specified key. It wraps a KeyValueStore.
type IdentityStore struct {
	kvstore simplekv.Store
	store   store.Store
}

// NewIdentityStore creates a new IdentityStore using the
// given KeyValueStore for backing storage.
func NewIdentityStore(kvstore simplekv.Store, store store.Store) *IdentityStore {
	return &IdentityStore{
		kvstore: kvstore,
		store:   store,
	}
}

// Put adds the given Identity to the store, returning the key that should
// be used to later retrieve the identity. The Identity will
// only be available in the store until the given expire time.
func (s *IdentityStore) Put(ctx context.Context, id *store.Identity, expire time.Time) (string, error) {
	entry := providerIdentityEntry{
		ProviderID: id.ProviderID,
		Expire:     expire,
	}
	b, err := json.Marshal(entry)
	if err != nil {
		// This should be impossible.
		panic(err)
	}
	hash := sha256.Sum256(b)
	key := base64.RawURLEncoding.EncodeToString(hash[:])
	if err := s.kvstore.Set(ctx, key, b, expire); err != nil {
		return "", errgo.Mask(err, errgo.Is(context.Canceled), errgo.Is(context.DeadlineExceeded))
	}
	return key, nil
}

// Get retrieves the Identity with the given key from the store. If
// there is no such token, or the token has expired, then the returned
// error will have a cause of store.ErrNotFound.
func (s *IdentityStore) Get(ctx context.Context, key string, id *store.Identity) error {
	b, err := s.kvstore.Get(ctx, key)
	if err != nil {
		if errgo.Cause(err) == simplekv.ErrNotFound {
			return errgo.WithCausef(err, store.ErrNotFound, "")
		}
		return errgo.Mask(err, errgo.Is(context.Canceled), errgo.Is(context.DeadlineExceeded))
	}
	var entry providerIdentityEntry
	if err := json.Unmarshal(b, &entry); err != nil {
		return errgo.Mask(err)
	}
	if entry.Expire.Before(time.Now()) {
		return errgo.WithCausef(nil, store.ErrNotFound, "%q not found", key)
	}
	id.ProviderID = entry.ProviderID
	err = s.store.Identity(ctx, id)
	if errgo.Cause(err) == store.ErrNotFound {
		err = errgo.WithCausef(nil, store.ErrNotFound, "%q not found", key)
	}
	return errgo.Mask(err, errgo.Is(store.ErrNotFound), errgo.Is(context.Canceled), errgo.Is(context.DeadlineExceeded))
}

type providerIdentityEntry struct {
	ProviderID store.ProviderIdentity
	Expire     time.Time
}
