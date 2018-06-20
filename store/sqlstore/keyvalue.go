// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sqlstore

import (
	"database/sql"
	"time"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/store"
)

// A providerDataStore implements store.ProviderDataStore.
type providerDataStore struct {
	b *backend
}

func (s *providerDataStore) KeyValueStore(_ context.Context, idp string) (store.KeyValueStore, error) {
	return &keyValueStore{
		backend: s.b,
		idp:     idp,
	}, nil
}

// A keyValueStore implements store.KeyValueStore.
type keyValueStore struct {
	*backend
	idp string
}

// Context implements idp.KeyValueStore.Context.
func (s *keyValueStore) Context(ctx context.Context) (context.Context, func()) {
	return ctx, func() {}
}

type providerDataParams struct {
	argBuilder

	Provider string
	Key      string
	Value    []byte
	Expire   nullTime
	Update   bool
}

// Get implements store.KeyValueStore.Get by selecting the blob with the
// given key from the provider_data table.
func (s *keyValueStore) Get(ctx context.Context, key string) ([]byte, error) {
	v, err := s.get(s.db, key, false)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(store.ErrNotFound))
	}
	return v, nil
}

// get is like Get except that it operates on a general queryer value.
func (s *keyValueStore) get(q queryer, key string, forUpdate bool) ([]byte, error) {
	params := &providerDataParams{
		argBuilder: s.driver.argBuilderFunc(),
		Provider:   s.idp,
		Key:        key,
	}
	var value []byte
	tmpl := tmplGetProviderData
	if forUpdate {
		tmpl = tmplGetProviderDataForUpdate
	}
	row, err := s.driver.queryRow(q, tmpl, params)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if err := row.Scan(&value); err != nil {
		if errgo.Cause(err) == sql.ErrNoRows {
			return nil, store.KeyNotFoundError(key)
		}
		return nil, errgo.Mask(err)
	}
	return value, nil
}

// Set implements store.KeyValueStore.Set by upserting the blob with the
// given key, value and expire time into the provider_data table.
func (s *keyValueStore) Set(ctx context.Context, key string, value []byte, expire time.Time) error {
	return s.set(s.db, key, value, expire)
}

// set is like Set except that it operates on a general queryer value.
func (s *keyValueStore) set(q queryer, key string, value []byte, expire time.Time) error {
	params := &providerDataParams{
		argBuilder: s.driver.argBuilderFunc(),
		Provider:   s.idp,
		Key:        key,
		Value:      value,
		Expire:     nullTime{expire, !expire.IsZero()},
		Update:     true,
	}
	_, err := s.driver.exec(q, tmplInsertProviderData, params)
	return errgo.Mask(err)
}

// Update implements store.KeyValueStore.Update.
func (s *keyValueStore) Update(ctx context.Context, key string, expire time.Time, getVal func(old []byte) ([]byte, error)) error {
	err := s.withTx(func(tx *sql.Tx) error {
		v, err := s.get(tx, key, true)
		if err != nil {
			if errgo.Cause(err) != store.ErrNotFound {
				return errgo.Mask(err)
			}
		} else if v == nil {
			v = []byte{}
		}
		newVal, err := getVal(v)
		if err != nil {
			return errgo.Mask(err, errgo.Any)
		}
		if err := s.set(tx, key, newVal, expire); err != nil {
			return errgo.Mask(err)
		}
		return nil
	})
	return errgo.Mask(err, errgo.Any)
}

// Add implements store.KeyValueStore.Add by inserting a blob with the
// given key, value and expire time into the provider_data table.
func (s *keyValueStore) Add(_ context.Context, key string, value []byte, expire time.Time) error {
	params := &providerDataParams{
		argBuilder: s.driver.argBuilderFunc(),
		Provider:   s.idp,
		Key:        key,
		Value:      value,
		Expire:     nullTime{expire, !expire.IsZero()},
		Update:     false,
	}
	_, err := s.driver.exec(s.db, tmplInsertProviderData, params)
	if s.driver.isDuplicateFunc(errgo.Cause(err)) {
		return store.DuplicateKeyError(key)
	}
	return errgo.Mask(err)
}
