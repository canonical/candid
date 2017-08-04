// Copyright 2017 Canonical Ltd.

package mgostore

import (
	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/mgorootkeystore"
	mgo "gopkg.in/mgo.v2"
)

const macaroonCollection = "macaroons"

type rootKeyStore struct {
	db     *Database
	policy mgorootkeystore.Policy
}

// Get implements bakery.RootKeyStore.Get by wrapping mgorootkeystore
// implementation with code to determine the collection.
func (s rootKeyStore) Get(ctx context.Context, id []byte) ([]byte, error) {
	coll := s.db.c(ctx, macaroonCollection)
	defer coll.Database.Session.Close()
	store := s.db.rootKeys.NewStore(coll, s.policy)
	return store.Get(ctx, id)
}

// RootKey implements bakery.RootKeyStore.RootKey by wrapping
// mgorootkeystore implementation with code to determine the collection.
func (s rootKeyStore) RootKey(ctx context.Context) ([]byte, []byte, error) {
	coll := s.db.c(ctx, macaroonCollection)
	defer coll.Database.Session.Close()
	store := s.db.rootKeys.NewStore(coll, s.policy)
	return store.RootKey(ctx)
}

func ensureBakeryIndexes(rk *mgorootkeystore.RootKeys, db *mgo.Database) error {
	if err := rk.EnsureIndex(db.C(macaroonCollection)); err != nil {
		return errgo.Mask(err)
	}
	return nil
}
