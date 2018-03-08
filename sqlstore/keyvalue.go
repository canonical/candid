// Copyright 2017 Canonical Ltd.

package sqlstore

import (
	"database/sql"
	"time"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/store"
)

// A providerDataStore implements store.ProviderDataStore.
type providerDataStore struct {
	db *Database
}

func (s *providerDataStore) KeyValueStore(_ context.Context, idp string) (store.KeyValueStore, error) {
	return &keyValueStore{
		Database: s.db,
		idp:      idp,
	}, nil
}

// A keyValueStore implements store.KeyValueStore.
type keyValueStore struct {
	*Database
	idp string
}

// Context implements idp.KeyValueStore.Context.
func (s *keyValueStore) Context(ctx context.Context) (context.Context, func()) {
	return ctx, func() {}
}

// Get implements store.KeyValueStore.Get by selecting the blob with the
// given key from the provider_data table.
func (s *keyValueStore) Get(_ context.Context, key string) ([]byte, error) {
	stmt := s.driver.Stmt(nil, stmtGetProviderData)
	var value []byte
	if err := stmt.QueryRow(s.idp, key).Scan(&value); err != nil {
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
	stmt := s.driver.Stmt(nil, stmtSetProviderData)
	_, err := stmt.Exec(s.idp, key, value, nullTime{expire, !expire.IsZero()})
	return errgo.Mask(err)
}

// Add implements store.KeyValueStore.Add by inserting a blob with the
// given key, value and expire time into the provider_data table.
func (s *keyValueStore) Add(ctx context.Context, key string, value []byte, expire time.Time) error {
	stmt := s.driver.Stmt(nil, stmtAddProviderData)
	_, err := stmt.Exec(s.idp, key, value, nullTime{expire, !expire.IsZero()})
	if s.driver.isDuplicateFunc(err) {
		return store.DuplicateKeyError(key)
	}
	return errgo.Mask(err)
}
