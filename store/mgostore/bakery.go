// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore

import (
	"context"

	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery/mgorootkeystore"
	mgo "gopkg.in/mgo.v2"
)

const macaroonCollection = "macaroons"

type rootKeyStore struct {
	b      *backend
	policy mgorootkeystore.Policy
}

// Get implements bakery.RootKeyStore.Get by wrapping mgorootkeystore
// implementation with code to determine the collection.
func (s rootKeyStore) Get(ctx context.Context, id []byte) ([]byte, error) {
	coll := s.b.c(ctx, macaroonCollection)
	defer coll.Database.Session.Close()
	store := s.b.rootKeys.NewStore(coll, s.policy)
	return store.Get(ctx, id)
}

// RootKey implements bakery.RootKeyStore.RootKey by wrapping
// mgorootkeystore implementation with code to determine the collection.
func (s rootKeyStore) RootKey(ctx context.Context) ([]byte, []byte, error) {
	coll := s.b.c(ctx, macaroonCollection)
	defer coll.Database.Session.Close()
	store := s.b.rootKeys.NewStore(coll, s.policy)
	return store.RootKey(ctx)
}

func ensureBakeryIndexes(rk *mgorootkeystore.RootKeys, db *mgo.Database) error {
	if err := rk.EnsureIndex(db.C(macaroonCollection)); err != nil {
		return errgo.Mask(err)
	}
	return nil
}
