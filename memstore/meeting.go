// Copyright 2017 Canonical Ltd.

package memstore

import (
	"time"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/meeting"
)

// NewMeetingStore creates a new in-memory meeting.Store implementation.
func NewMeetingStore() meeting.Store {
	return &meetingStore{
		data: make(map[string]meetingStoreEntry),
	}
}

type meetingStore struct {
	data map[string]meetingStoreEntry
}

type meetingStoreEntry struct {
	address string
	time    time.Time
}

// Context implements meeting.Store.Context by returning the given
// context unchanged along with a NOP close function.
func (s *meetingStore) Context(ctx context.Context) (_ context.Context, close func()) {
	return ctx, func() {}
}

// Put implements meeting.Store.Put.
func (s *meetingStore) Put(_ context.Context, id, address string) error {
	s.data[id] = meetingStoreEntry{
		address: address,
		time:    time.Now(),
	}
	return nil
}

// Get implements meeting.Store.Get.
func (s *meetingStore) Get(_ context.Context, id string) (address string, _ error) {
	if e, ok := s.data[id]; ok {
		return e.address, nil
	}
	return "", errgo.New("rendezvous not found, probably expired")
}

// Remove implements meeting.Store.Remove.
func (s *meetingStore) Remove(_ context.Context, id string) (time.Time, error) {
	e := s.data[id]
	delete(s.data, id)
	return e.time, nil
}

// RemoveOld implements meeting.Store.RemoveOld.
func (s *meetingStore) RemoveOld(_ context.Context, addr string, olderThan time.Time) (ids []string, err error) {
	for k, v := range s.data {
		if v.time.Before(olderThan) {
			delete(s.data, k)
			ids = append(ids, k)
		}
	}
	return ids, nil
}
