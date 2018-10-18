// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore

import (
	"strconv"
	"time"

	"github.com/juju/utils/debugstatus"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type doc struct {
	Id      string `bson:"_id"`
	Addr    string
	Created time.Time
}

const meetingCollection = "meeting"

// meetingStore is an implementation of meeting.Store that uses a mongodb
// collection for the persistent data store.
type meetingStore struct {
	b *backend
}

// Context implements meeting.Store.Context.
func (s *meetingStore) Context(ctx context.Context) (_ context.Context, cancel func()) {
	return s.b.context(ctx)
}

// Put implements meeting.Store.Put.
func (s *meetingStore) Put(ctx context.Context, id, address string) error {
	return s.put(ctx, id, address, time.Now())
}

// put is the internal version of Put which takes a time
// for testing purposes.
func (s *meetingStore) put(ctx context.Context, id, address string, now time.Time) error {
	coll := s.b.c(ctx, meetingCollection)
	defer coll.Database.Session.Close()

	err := coll.Insert(&doc{
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
func (s *meetingStore) Get(ctx context.Context, id string) (address string, err error) {
	coll := s.b.c(ctx, meetingCollection)
	defer coll.Database.Session.Close()

	var entry doc
	err = coll.FindId(id).One(&entry)
	if err == mgo.ErrNotFound {
		err = errgo.Newf("rendezvous not found, probably expired")
	}
	if err != nil {
		return "", errgo.Mask(err)
	}
	return entry.Addr, nil
}

// Remove implements meeting.Store.Remove.
func (s *meetingStore) Remove(ctx context.Context, id string) (time.Time, error) {
	coll := s.b.c(ctx, meetingCollection)
	defer coll.Database.Session.Close()

	var entry doc
	change := mgo.Change{
		Remove: true,
	}
	_, err := coll.FindId(id).Apply(change, &entry)
	if err == mgo.ErrNotFound {
		return time.Time{}, nil
	}
	if err != nil && err != mgo.ErrNotFound {
		return time.Time{}, errgo.Mask(err)
	}
	return entry.Created, nil
}

// RemoveOld implements meeting.Store.RemoveOld.
func (s *meetingStore) RemoveOld(ctx context.Context, addr string, olderThan time.Time) (ids []string, err error) {
	coll := s.b.c(ctx, meetingCollection)
	defer coll.Database.Session.Close()

	query := bson.D{{"created", bson.D{{"$lt", olderThan}}}}
	if addr != "" {
		query = append(query, bson.DocElem{"addr", addr})
	}
	iter := coll.Find(query).Select(nil).Iter()
	var entry doc
	for iter.Next(&entry) {
		err := coll.RemoveId(entry.Id)
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

var indexes = []mgo.Index{{
	Key: []string{"addr", "created"},
}, {
	Key: []string{"created"},
}}

func ensureMeetingIndexes(db *mgo.Database) error {
	coll := db.C(meetingCollection)
	for _, idx := range indexes {
		if err := coll.EnsureIndex(idx); err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

func (b *backend) meetingStatus(ctx context.Context) (key string, result debugstatus.CheckResult) {
	result.Name = "count of meeting collection"
	result.Passed = true
	coll := b.c(ctx, meetingCollection)
	defer coll.Database.Session.Close()
	c, err := coll.Count()
	result.Value = strconv.Itoa(c)
	if err != nil {
		result.Value = err.Error()
		result.Passed = false
	}
	return "meeting_count", result
}
