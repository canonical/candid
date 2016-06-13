// Copyright 2015 Canonical Ltd.

package mgomeeting

import (
	"time"

	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/meeting"
)

type doc struct {
	Id      string `bson:"_id"`
	Addr    string
	Created time.Time
}

type store struct {
	coll *mgo.Collection
}

// NewStore returns an implementation of meeting.Store
// that uses the given collection as a persistent data store.
func NewStore(coll *mgo.Collection) meeting.Store {
	return store{coll}
}

// Put implements meeting.Store.Put.
func (s store) Put(id, address string) error {
	return s.put(id, address, time.Now())
}

// put is the internal version of Put which takes a time
// for testing purposes.
func (s store) put(id, address string, now time.Time) error {
	err := s.coll.Insert(&doc{
		Id:      id,
		Addr:    address,
		Created: now,
	})
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

var indexes = []mgo.Index{{
	Key: []string{"addr", "created"},
}, {
	Key: []string{"created"},
}}

// CreateCollection creates a collection for use as a Store
// along with its required indexes. If the collection
// has already been created, this does nothing.
func CreateCollection(coll *mgo.Collection) error {
	for _, idx := range indexes {
		err := coll.EnsureIndex(idx)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

// Get implements meeting.Store.Get.
func (s store) Get(id string) (address string, err error) {
	var entry doc
	err = s.coll.FindId(id).One(&entry)
	if err == mgo.ErrNotFound {
		err = errgo.Newf("rendezvous not found, probably expired")
	}
	if err != nil {
		return "", errgo.Mask(err)
	}
	return entry.Addr, nil
}

// Remove implements meeting.Store.Remove.
func (s store) Remove(id string) (time.Time, error) {
	var entry doc
	change := mgo.Change{
		Remove: true,
	}
	_, err := s.coll.FindId(id).Apply(change, &entry)
	if err == mgo.ErrNotFound {
		return time.Time{}, nil
	}
	if err != nil && err != mgo.ErrNotFound {
		return time.Time{}, errgo.Mask(err)
	}
	return entry.Created, nil
}

// RemoveOld implements meeting.Store.RemoveOld.
func (s store) RemoveOld(addr string, olderThan time.Time) (ids []string, err error) {
	query := bson.D{{"created", bson.D{{"$lt", olderThan}}}}
	if addr != "" {
		query = append(query, bson.DocElem{"addr", addr})
	}
	iter := s.coll.Find(query).Select(nil).Iter()
	var entry doc
	for iter.Next(&entry) {
		err := s.coll.RemoveId(entry.Id)
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

// Close implements meeting.Store.Close.
// It is a no-op.
func (s store) Close() {
}
