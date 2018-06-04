// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package memstore

import (
	"sync"
	"time"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/store"
)

// NewProviderDataStore creates a new in-memory store.ProviderDataStore.
func NewProviderDataStore() store.ProviderDataStore {
	return &providerDataStore{
		data: make(map[string]map[string][]byte),
	}
}

type providerDataStore struct {
	mu   sync.Mutex
	data map[string]map[string][]byte
}

// KeyValueStore implements store.ProviderDataStore.KeyValueStore.
func (s *providerDataStore) KeyValueStore(_ context.Context, idp string) (store.KeyValueStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data[idp] == nil {
		s.data[idp] = make(map[string][]byte)
	}
	return keyValueStore{
		store: s,
		idp:   idp,
	}, nil
}

type keyValueStore struct {
	store *providerDataStore
	idp   string
}

// Context implements store.KeyValueStore.Context by return the given
// context unchanged and a nop close function.
func (s keyValueStore) Context(ctx context.Context) (_ context.Context, close func()) {
	return ctx, func() {}
}

// Get implements store.KeyValueStore.Get.
func (s keyValueStore) Get(_ context.Context, key string) ([]byte, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	v, ok := s.store.data[s.idp][key]
	if !ok {
		return nil, store.KeyNotFoundError(key)
	}
	return v, nil
}

// Set implements store.KeyValueStore.Set.
func (s keyValueStore) Set(_ context.Context, key string, value []byte, _ time.Time) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if value == nil {
		value = []byte{}
	}
	s.store.data[s.idp][key] = value
	return nil
}

func (s keyValueStore) Update(ctx context.Context, key string, expire time.Time, getVal func(old []byte) ([]byte, error)) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	data := s.store.data[s.idp]
	newVal, err := getVal(data[key])
	if err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	if newVal == nil {
		newVal = []byte{}
	}
	data[key] = newVal
	return nil
}
