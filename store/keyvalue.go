// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package store

import (
	"time"

	"golang.org/x/net/context"
)

// A KeyValueStore is a store that associates a value with a specified
// key.
type KeyValueStore interface {
	// Context returns a context that is suitable for passing to the
	// other KeyValueStore methods. KeyValueStore methods called with
	// such a context will be sequentially consistent; for example, a
	// value that is set in Set will immediately be available from
	// Get.
	//
	// The returned close function must be called when the returned
	// context will no longer be used, to allow for any required
	// cleanup.
	Context(ctx context.Context) (_ context.Context, close func())

	// Get retrieves the value associated with the given key. If
	// there is no such key an error with a cause of ErrNotFound will
	// be returned.
	Get(ctx context.Context, key string) ([]byte, error)

	// Set updates the given key to have the specified value.
	//
	// If the expire time is non-zero then the entry may be garbage
	// collected at some point after that time. Clients should not
	// rely on the value being removed at the given time.
	Set(ctx context.Context, key string, value []byte, expire time.Time) error

	// Add is like Set except that if the key already has a value
	// associated with it it returns an error with the cause of
	// ErrDuplicateKey.
	//
	// If the expire time is non-zero then the entry may be garbage
	// collected at some point after that time. Clients should not
	// rely on the value being removed at the given time.
	Add(ctx context.Context, key string, value []byte, expire time.Time) error
}

// An ProviderDataStore is a data store that supports identity provider
// specific KeyValueStores. These stores can be used by identity
// providers to store data that is not directly related to an identity.
type ProviderDataStore interface {
	// KeyValueStore gets a KeyValueStore for use by the given
	// identity provider.
	KeyValueStore(ctx context.Context, idp string) (KeyValueStore, error)
}
