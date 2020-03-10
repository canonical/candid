// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package memstore

import (
	"context"
	"sync"
	"time"

	errgo "gopkg.in/errgo.v1"

	"github.com/canonical/candid/meeting"
)

// NewMeetingStore creates a new in-memory meeting.Store implementation.
func NewMeetingStore() meeting.Store {
	return &meetingStore{
		data: make(map[string]meetingStoreEntry),
	}
}

type meetingStore struct {
	mu   sync.Mutex
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
func (s *meetingStore) Put(ctx context.Context, id, address string) error {
	return errgo.Mask(s.put(ctx, id, address, time.Now()))
}

// put is the internal version of Put which takes a time
// for testing purposes.
func (s *meetingStore) put(_ context.Context, id, address string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[id]; ok {
		return errgo.Newf("duplicate id %q in meeting store", id)
	}
	s.data[id] = meetingStoreEntry{
		address: address,
		time:    now,
	}
	return nil
}

// Get implements meeting.Store.Get.
func (s *meetingStore) Get(_ context.Context, id string) (address string, _ error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.data[id]; ok {
		return e.address, nil
	}
	return "", errgo.New("rendezvous not found, probably expired")
}

// Remove implements meeting.Store.Remove.
func (s *meetingStore) Remove(_ context.Context, id string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.data[id]
	delete(s.data, id)
	return e.time, nil
}

// RemoveOld implements meeting.Store.RemoveOld.
func (s *meetingStore) RemoveOld(_ context.Context, addr string, olderThan time.Time) (ids []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.data {
		if addr != "" && v.address != addr {
			continue
		}
		if v.time.Before(olderThan) {
			delete(s.data, k)
			ids = append(ids, k)
		}
	}
	return ids, nil
}
