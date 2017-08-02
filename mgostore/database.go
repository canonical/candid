// Copyright 2017 Canonical Ltd.

package mgostore

import (
	"golang.org/x/net/context"
	mgo "gopkg.in/mgo.v2"

	"github.com/CanonicalLtd/blues-identity/meeting"
	"github.com/CanonicalLtd/blues-identity/store"
)

// A Database provides a wrapper around a single mongodb database that
// can be used as the persistent storage for the various types of store
// required by the identity service.
type Database struct {
	db *mgo.Database
}

// NewDatabase creates a new Database using the given *mgo.Database. The
// given Database's underlying session will be copied. The Database must
// be closed when finished with.
func NewDatabase(db *mgo.Database) (*Database, error) {
	// TODO(mhilton) these indexes are interfering with the rest of the
	// system, re-enable when fully switched.
	//	if err := ensureIdentityIndexes(db); err != nil {
	//		return nil, err
	//	}
	if err := ensureMeetingIndexes(db); err != nil {
		return nil, err
	}
	return &Database{db.With(db.Session.Copy())}, nil
}

// Close cleans up resources associated with the database.
func (d *Database) Close() {
	d.db.Session.Close()
}

// context returns a context with session information attached such that
// subsequent operations that use the context will be consistent. This
// function may return the context it was passed if suitable session
// information is already available. The return close function should
// always be called once the context is not longer needed.
func (d *Database) context(ctx context.Context) (_ context.Context, close func()) {
	if s, _ := ctx.Value(sessionKey{}).(*mgo.Session); s != nil {
		return ctx, func() {}
	}
	// TODO (mhilton) add some more advanced session pooling.
	s := d.db.Session.Copy()
	return context.WithValue(ctx, sessionKey{}, s), s.Close
}

type sessionKey struct{}

// s returns a *mgo.Session for use in subsequent queries. The returned
// session must be closed once finished with.
func (d *Database) s(ctx context.Context) *mgo.Session {
	if s, _ := ctx.Value(sessionKey{}).(*mgo.Session); s != nil {
		return s.Clone()
	}
	return d.db.Session.Copy()
}

// c returns a *mgo.Collection with the given name in the current
// database. The collection's underlying session must be closed when the
// query is complete.
func (d *Database) c(ctx context.Context, name string) *mgo.Collection {
	return d.db.C(name).With(d.s(ctx))
}

// Store returns a new store.Store implementation using this database for
// persistent storage.
func (d *Database) Store() store.Store {
	// TODO(mhilton) this is only necessary temporarily until all
	// modules use the new store.
	if err := ensureIdentityIndexes(d.db); err != nil {
		panic(err)
	}
	return &identityStore{d}
}

// MeetingStore returns a new meeting.Store implementation using this
// database for persistent storage.
func (d *Database) MeetingStore() meeting.Store {
	return &meetingStore{d}
}
