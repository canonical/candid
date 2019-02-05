// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package store

import (
	"context"

	"github.com/juju/simplekv"
)

// An ProviderDataStore is a data store that supports identity provider
// specific KeyValueStores. These stores can be used by identity
// providers to store data that is not directly related to an identity.
type ProviderDataStore interface {
	// KeyValueStore gets a key-value store for use by the given
	// identity provider.
	KeyValueStore(ctx context.Context, idp string) (simplekv.Store, error)
}
