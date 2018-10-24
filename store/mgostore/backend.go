// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore

import (
	"time"

	"github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/mgosimplekv"
	"github.com/juju/utils/debugstatus"
	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/mgorootkeystore"
	mgo "gopkg.in/mgo.v2"

	"github.com/CanonicalLtd/candid/meeting"
	"github.com/CanonicalLtd/candid/store"
)

const aclsCollection = "acls"

// backend provides a wrapper around a single mongodb database that
// can be used as the persistent storage for the various types of store
// required by the identity service.
type backend struct {
	db       *mgo.Database
	rootKeys *mgorootkeystore.RootKeys
	aclStore aclstore.ACLStore
}

// NewBackend creates a new Backend instance using the given
// *mgo.Database. The given Database's underlying session will be
// copied. The Backend must be closed when finished with.
func NewBackend(db *mgo.Database) (store.Backend, error) {
	if err := ensureIdentityIndexes(db); err != nil {
		return nil, errgo.Mask(err)
	}
	if err := ensureMeetingIndexes(db); err != nil {
		return nil, errgo.Mask(err)
	}
	rk := mgorootkeystore.NewRootKeys(1000) // TODO(mhilton) make this configurable?
	if err := ensureBakeryIndexes(rk, db); err != nil {
		return nil, errgo.Mask(err)
	}
	aclStore, err := mgosimplekv.NewStore(db.C(aclsCollection))
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &backend{
		db:       db.With(db.Session.Copy()),
		rootKeys: rk,
		aclStore: aclstore.NewACLStore(aclStore),
	}, nil
}

// Close cleans up resources associated with the database.
func (b *backend) Close() {
	b.db.Session.Close()
}

// context returns a context with session information attached such that
// subsequent operations that use the context will be consistent. This
// function may return the context it was passed if suitable session
// information is already available. The return close function should
// always be called once the context is not longer needed.
func (b *backend) context(ctx context.Context) (_ context.Context, close func()) {
	if s, _ := ctx.Value(sessionKey{}).(*mgo.Session); s != nil {
		return ctx, func() {}
	}
	// TODO (mhilton) add some more advanced session pooling.
	s := b.db.Session.Copy()
	return context.WithValue(ctx, sessionKey{}, s), s.Close
}

type sessionKey struct{}

// s returns a *mgo.Session for use in subsequent queries. The returned
// session must be closed once finished with.
func (b *backend) s(ctx context.Context) *mgo.Session {
	if s, _ := ctx.Value(sessionKey{}).(*mgo.Session); s != nil {
		return s.Clone()
	}
	return b.db.Session.Copy()
}

// c returns a *mgo.Collection with the given name in the current
// database. The collection's underlying session must be closed when the
// query is complete.
func (b *backend) c(ctx context.Context, name string) *mgo.Collection {
	return b.db.C(name).With(b.s(ctx))
}

// Store implements store.Backend.Store.
func (b *backend) Store() store.Store {
	return &identityStore{b}
}

// MeetingStore implements store.Backend.MeetingStore.
func (b *backend) MeetingStore() meeting.Store {
	return &meetingStore{b}
}

// BakeryRootKeyStore implements store.Backend.BakeryRootKeyStore.
func (b *backend) BakeryRootKeyStore() bakery.RootKeyStore {
	return &rootKeyStore{
		b: b,
		policy: mgorootkeystore.Policy{
			ExpiryDuration: 365 * 24 * time.Hour,
		},
	}
}

// ProviderDataStore implements store.Backend.ProviderDataStore.
func (b *backend) ProviderDataStore() store.ProviderDataStore {
	return &providerDataStore{b}
}

// DebugStatusCheckerFuncs implements store.Backend.DebugStatusCheckerFuncs.
func (b *backend) DebugStatusCheckerFuncs() []debugstatus.CheckerFunc {
	return []debugstatus.CheckerFunc{
		debugstatus.MongoCollections(collector{b.db}),
		b.meetingStatus,
	}
}

// ACLStore implements store.Backend.ACLStore.
func (b *backend) ACLStore() aclstore.ACLStore {
	return b.aclStore
}

type collector struct {
	db *mgo.Database
}

// Collections implements debugstatus.Collector.Collections.
func (c collector) Collections() []*mgo.Collection {
	return []*mgo.Collection{
		c.db.C(macaroonCollection),
		c.db.C(meetingCollection),
		c.db.C(identitiesCollection),
		c.db.C(aclsCollection),
	}
}

// CollectionNames implements debugstatus.Collector.CollectionNames by
// wrapping the CollectionNames method of mgo.Database with some session
// handling code.
func (c collector) CollectionNames() ([]string, error) {
	s := c.db.Session.Copy()
	defer s.Close()
	return c.db.With(s).CollectionNames()
}
