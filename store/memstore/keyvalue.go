// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package memstore

import (
	"sync"

	"github.com/juju/simplekv"
	"github.com/juju/simplekv/memsimplekv"
	"golang.org/x/net/context"

	"github.com/CanonicalLtd/candid/store"
)

// NewProviderDataStore creates a new in-memory store.ProviderDataStore.
func NewProviderDataStore() store.ProviderDataStore {
	return &providerDataStore{
		stores: make(map[string]simplekv.Store),
	}
}

type providerDataStore struct {
	mu     sync.Mutex
	stores map[string]simplekv.Store
}

// KeyValueStore implements store.ProviderDataStore.KeyValueStore.
func (s *providerDataStore) KeyValueStore(_ context.Context, idp string) (simplekv.Store, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stores[idp] == nil {
		s.stores[idp] = memsimplekv.NewStore()
	}
	return s.stores[idp], nil
}
