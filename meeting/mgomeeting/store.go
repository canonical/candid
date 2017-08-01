// Copyright 2015 Canonical Ltd.

package mgomeeting

import (
	"time"

	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/mgoctx"
)

type doc struct {
	Id      string `bson:"_id"`
	Addr    string
	Created time.Time
}

// Store is an implementation of meeting.Store that uses a mongodb
// collection for the persistent data store.
type Store struct {
	coll mgo.Collection
}

var indexes = []mgo.Index{{
	Key: []string{"addr", "created"},
}, {
	Key: []string{"created"},
}}

// NewStore returns an implementation of meeting.Store that uses the
// given collection as a persistent data store.
//
// The session associated with the given collection will be copied before
// use and the Store must be closed when finished with.
func NewStore(coll *mgo.Collection) (*Store, error) {
	coll = coll.With(coll.Database.Session.Copy())
	for _, idx := range indexes {
		if err := coll.EnsureIndex(idx); err != nil {
			return nil, errgo.Mask(err)
		}
	}
	return &Store{*coll}, nil
}

// Context implements meeting.Store.Context.
func (s *Store) Context(ctx context.Context) (_ context.Context, cancel func()) {
	sess, ok := s.session(ctx)
	if ok {
		return ctx, func() {}
	}
	return mgoctx.ContextWithSession(ctx, sess), sess.Close
}

// Put implements meeting.Store.Put.
func (s *Store) Put(ctx context.Context, id, address string) error {
	return s.put(ctx, id, address, time.Now())
}

// put is the internal version of Put which takes a time
// for testing purposes.
func (s *Store) put(ctx context.Context, id, address string, now time.Time) error {
	sess, ok := s.session(ctx)
	if !ok {
		defer sess.Close()
	}
	err := s.coll.With(sess).Insert(&doc{
		Id:      id,
		Addr:    address,
		Created: now,
	})
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// Get implements meeting.Store.Get.
func (s *Store) Get(ctx context.Context, id string) (address string, err error) {
	sess, ok := s.session(ctx)
	if !ok {
		defer sess.Close()
	}
	var entry doc
	err = s.coll.With(sess).FindId(id).One(&entry)
	if err == mgo.ErrNotFound {
		err = errgo.Newf("rendezvous not found, probably expired")
	}
	if err != nil {
		return "", errgo.Mask(err)
	}
	return entry.Addr, nil
}

// Remove implements meeting.Store.Remove.
func (s *Store) Remove(ctx context.Context, id string) (time.Time, error) {
	sess, ok := s.session(ctx)
	if !ok {
		defer sess.Close()
	}
	var entry doc
	change := mgo.Change{
		Remove: true,
	}
	_, err := s.coll.With(sess).FindId(id).Apply(change, &entry)
	if err == mgo.ErrNotFound {
		return time.Time{}, nil
	}
	if err != nil && err != mgo.ErrNotFound {
		return time.Time{}, errgo.Mask(err)
	}
	return entry.Created, nil
}

// RemoveOld implements meeting.Store.RemoveOld.
func (s *Store) RemoveOld(ctx context.Context, addr string, olderThan time.Time) (ids []string, err error) {
	sess, ok := s.session(ctx)
	if !ok {
		defer sess.Close()
	}
	query := bson.D{{"created", bson.D{{"$lt", olderThan}}}}
	if addr != "" {
		query = append(query, bson.DocElem{"addr", addr})
	}
	iter := s.coll.With(sess).Find(query).Select(nil).Iter()
	var entry doc
	for iter.Next(&entry) {
		err := s.coll.With(sess).RemoveId(entry.Id)
		if err != nil {
			return ids, errgo.Notef(err, "cannot remove %q", entry.Id)
		}
		ids = append(ids, entry.Id)
	}
	if err := iter.Err(); err != nil {
		return ids, errgo.Mask(err)
	}
	return ids, nil
}

// Close cleans up resources associated with the mongodb session.
func (s *Store) Close() {
	s.coll.Database.Session.Close()
}

func (s *Store) session(ctx context.Context) (_ *mgo.Session, fromContext bool) {
	if sess := mgoctx.SessionFromContext(ctx); sess != nil {
		return sess, true
	}
	return s.coll.Database.Session.Copy(), false
}
