package store

import (
	"sync"
	"time"

	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/meeting"
)

// meetingStore implements the meeting.Store interface.
// TODO Currently it's in-memory only (which is broken if
// there's more than one server). Make it use MongoDB.
type meetingStore struct {
	mu      sync.Mutex
	entries map[string]string
}

func newMeetingStore() meeting.Store {
	return &meetingStore{
		entries: make(map[string]string),
	}
}

// Put implements Store.Put.
func (s meetingStore) Put(id, address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[id] = address
	return nil
}

// Get implements Store.Get.
func (s meetingStore) Get(id string) (address string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	addr, ok := s.entries[id]
	if !ok {
		return "", errgo.Newf("rendezvous %q not found", id)
	}
	return addr, nil
}

// Remove implements Store.Remove.
func (s meetingStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, id)
	return nil
}

// RemoveOld implements Store.RemoveOld.
func (s meetingStore) RemoveOld(address string, olderThan time.Time) (ids []string, err error) {
	return nil, errgo.Newf("RemoveOld not implemented")
}
