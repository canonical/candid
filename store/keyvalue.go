// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package store

import (
	"time"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
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

	// Update updates the value for the given key. The getVal
	// function is called with the old value of the key and should
	// return the new value, which will be updated atomically;
	// getVal may be called several times, so should not have
	// side-effects.
	//
	// If an entry for the given key did not previously exist, old
	// will be nil.
	//
	// If getVal returns an error, it will be returned by Update with
	// its cause unchanged.
	//
	// If the expire time is non-zero then the entry may be garbage
	// collected at some point after that time. Clients should not
	// rely on the value being removed at the given time.
	Update(ctx context.Context, key string, expire time.Time, getVal func(old []byte) ([]byte, error)) error
}

// SetKeyOnce is like KeyValueStore.Set except that if the key already
// has a value associated with it it returns an error with the cause of
// ErrDuplicateKey.
func SetKeyOnce(ctx context.Context, kv KeyValueStore, key string, value []byte, expire time.Time) error {
	err := kv.Update(ctx, key, expire, func(old []byte) ([]byte, error) {
		if old != nil {
			return nil, DuplicateKeyError(key)
		}
		return value, nil
	})
	return errgo.Mask(err, errgo.Any)
}

// An ProviderDataStore is a data store that supports identity provider
// specific KeyValueStores. These stores can be used by identity
// providers to store data that is not directly related to an identity.
type ProviderDataStore interface {
	// KeyValueStore gets a KeyValueStore for use by the given
	// identity provider.
	KeyValueStore(ctx context.Context, idp string) (KeyValueStore, error)
}
