// Copyright 2015 Canonical Ltd.

package mgomeeting

import (
	"time"

	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"

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
	err := s.coll.Insert(&doc{
		Id:      id,
		Addr:    address,
		Created: time.Now(),
	})
	if err != nil {
		return errgo.Mask(err)
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
func (s store) Remove(id string) error {
	err := s.coll.RemoveId(id)
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// RemoveOld implements meeting.Store.RemoveOld.
func (s store) RemoveOld(address string, olderThan time.Time) (ids []string, err error) {
	return nil, errgo.Newf("RemoveOld not implemented")
}

// Close implements meeting.Store.Close.
// It is a no-op.
func (s store) Close() {
}
