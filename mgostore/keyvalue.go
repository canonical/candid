// Copyright 2017 Canonical Ltd.

package mgostore

import (
	"time"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	mgo "gopkg.in/mgo.v2"

	"github.com/CanonicalLtd/blues-identity/store"
)

// an idpDataStore implements store.IDPDataStore.
type idpDataStore struct {
	db *Database
}

func (s *idpDataStore) KeyValueStore(ctx context.Context, idp string) (store.KeyValueStore, error) {
	collection := "kv-idp-" + idp
	coll := s.db.c(ctx, collection)
	defer coll.Database.Session.Close()

	if err := coll.EnsureIndex(mgo.Index{Key: []string{"expire"}, ExpireAfter: time.Nanosecond}); err != nil {
		return nil, errgo.Mask(err)
	}

	return &keyValueStore{
		db:         s.db,
		collection: collection,
	}, nil
}

// a keyValueStore implements store.KeyValueStore.
type keyValueStore struct {
	db         *Database
	collection string
}

// Context implements idp.KeyValueStore.Context.
func (s *keyValueStore) Context(ctx context.Context) (context.Context, func()) {
	return s.db.context(ctx)
}

type kvDoc struct {
	Key    string     `bson:"_id,omitempty"`
	Value  []byte     `bson:",omitempty"`
	Expire time.Time `bson:",omitempty"`
}

// Get implements store.KeyValueStore.Get by retrieving the document with
// the given key from the store's collection.
func (s *keyValueStore) Get(ctx context.Context, key string) ([]byte, error) {
	coll := s.db.c(ctx, s.collection)
	defer coll.Database.Session.Close()

	var doc kvDoc
	if err := coll.FindId(key).One(&doc); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return nil, store.KeyNotFoundError(key)
		}
		return nil, errgo.Mask(err)
	}
	return doc.Value, nil
}

// Set implements store.KeyValueStore.Set by upserting the document with
// the given key, value and expire time into the store's collection.
func (s *keyValueStore) Set(ctx context.Context, key string, value []byte, expire time.Time) error {
	coll := s.db.c(ctx, s.collection)
	defer coll.Database.Session.Close()

	_, err := coll.UpsertId(key, kvDoc{
		Key: key,
		Value:  value,
		Expire: expire,
	})
	return errgo.Mask(err)
}

// Add implements store.KeyValueStore.Add by inserting a document with
// the given key, value and expire time into the store's collection.
func (s *keyValueStore) Add(ctx context.Context, key string, value []byte, expire time.Time) error {
	coll := s.db.c(ctx, s.collection)
	defer coll.Database.Session.Close()

	doc := kvDoc{
		Key:    key,
		Value:  value,
		Expire: expire,
	}

	if err := coll.Insert(doc); err != nil {
		if mgo.IsDup(err) {
			return store.DuplicateKeyError(key)
		}
		return errgo.Mask(err)
	}
	return nil
}
