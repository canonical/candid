// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore

import (
	"bytes"
	"time"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	retry "gopkg.in/retry.v1"

	"github.com/CanonicalLtd/candid/store"
)

// an providerDataStore implements store.ProviderDataStore.
type providerDataStore struct {
	backend *backend
}

func (s *providerDataStore) KeyValueStore(ctx context.Context, idp string) (store.KeyValueStore, error) {
	collection := "kv" + idp
	coll := s.backend.c(ctx, collection)
	defer coll.Database.Session.Close()

	if err := coll.EnsureIndex(mgo.Index{Key: []string{"expire"}, ExpireAfter: time.Nanosecond}); err != nil {
		return nil, errgo.Mask(err)
	}
	return &keyValueStore{
		backend:    s.backend,
		collection: collection,
	}, nil
}

// a keyValueStore implements store.KeyValueStore.
type keyValueStore struct {
	backend    *backend
	collection string
}

// Context implements idp.KeyValueStore.Context.
func (s *keyValueStore) Context(ctx context.Context) (context.Context, func()) {
	return s.backend.context(ctx)
}

type kvDoc struct {
	Key    string    `bson:"_id"`
	Value  []byte    `bson:"value'`
	Expire time.Time `bson:",omitempty"`
}

// Get implements store.KeyValueStore.Get by retrieving the document with
// the given key from the store's collection.
func (s *keyValueStore) Get(ctx context.Context, key string) ([]byte, error) {
	coll := s.backend.c(ctx, s.collection)
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
	coll := s.backend.c(ctx, s.collection)
	defer coll.Database.Session.Close()

	_, err := coll.UpsertId(key, bson.D{{
		"$set", bson.D{{
			"value", value,
		}, {
			"expire", expire,
		}},
	}})
	return errgo.Mask(err)
}

var updateStrategy = retry.Exponential{
	Initial:  time.Microsecond,
	Factor:   2,
	MaxDelay: 500 * time.Millisecond,
	Jitter:   true,
}

func (s *keyValueStore) Update(ctx context.Context, key string, expire time.Time, getVal func(old []byte) ([]byte, error)) error {
	coll := s.backend.c(ctx, s.collection)
	defer coll.Database.Session.Close()

	for r := retry.Start(updateStrategy, nil); r.Next(); {
		var doc kvDoc
		if err := coll.Find(bson.D{{"_id", key}}).One(&doc); err != nil {
			if errgo.Cause(err) != mgo.ErrNotFound {
				return errgo.Mask(err)
			}
			newVal, err := getVal(nil)
			if err != nil {
				return errgo.Mask(err, errgo.Any)
			}
			err = coll.Insert(kvDoc{
				Key:    key,
				Value:  newVal,
				Expire: expire,
			})
			if err == nil {
				return nil
			}
			if !mgo.IsDup(err) {
				return errgo.Mask(err)
			}
			// A new document has been inserted after we did the FindId and before Insert,
			// so try again.
			continue
		}
		newVal, err := getVal(doc.Value)
		if err != nil {
			return errgo.Mask(err, errgo.Any)
		}
		if bytes.Equal(newVal, doc.Value) {
			return nil
		}
		err = coll.Update(bson.D{{
			"_id", key,
		}, {
			"value", doc.Value,
		}}, bson.D{{
			"$set", bson.D{{
				"value", newVal,
			}, {
				"expire", expire,
			}},
		}})
		if err == nil {
			return nil
		}
		if err != mgo.ErrNotFound {
			return errgo.Mask(err)
		}
		// The document has been removed or updated since we retrieved it,
		// so try again.
	}
	return errgo.Newf("too many retry attempts trying to update key")
}
