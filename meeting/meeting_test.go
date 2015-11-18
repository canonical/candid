// Copyright 2014 Canonical Ltd.

package meeting_test

import (
	"sync"
	"time"

	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/meeting"
)

type suite struct{}

var _ = gc.Suite(&suite{})

func (*suite) TestRendezvousWaitBeforeDone(c *gc.C) {
	m, err := meeting.New(newFakeStore(), "localhost")
	c.Assert(err, gc.IsNil)
	defer m.Close()
	id, err := m.NewRendezvous([]byte("first data"))
	c.Assert(err, gc.IsNil)
	c.Assert(id, gc.Not(gc.Equals), "")

	waitDone := make(chan struct{})
	go func() {
		data0, data1, err := m.Wait(id)
		c.Check(err, gc.IsNil)
		c.Check(string(data0), gc.Equals, "first data")
		c.Check(string(data1), gc.Equals, "second data")

		close(waitDone)
	}()

	time.Sleep(10 * time.Millisecond)
	err = m.Done(id, []byte("second data"))
	c.Assert(err, gc.IsNil)
	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		c.Errorf("timed out waiting for rendezvous")
	}

	// Check that item has now been deleted.
	data0, data1, err := m.Wait(id)
	c.Assert(data0, gc.IsNil)
	c.Assert(data1, gc.IsNil)
	c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`)
}

func (*suite) TestRendezvousDoneBeforeWait(c *gc.C) {
	m, err := meeting.New(newFakeStore(), "localhost")
	c.Assert(err, gc.IsNil)
	defer m.Close()
	id, err := m.NewRendezvous([]byte("first data"))
	c.Assert(err, gc.IsNil)
	c.Assert(id, gc.Not(gc.Equals), "")

	err = m.Done(id, []byte("second data"))
	c.Assert(err, gc.IsNil)

	err = m.Done(id, []byte("other second data"))
	c.Assert(err, gc.ErrorMatches, `.*rendezvous ".*" done twice`)

	data0, data1, err := m.Wait(id)
	c.Assert(err, gc.IsNil)
	c.Assert(string(data0), gc.Equals, "first data")
	c.Assert(string(data1), gc.Equals, "second data")

	// Check that item has now been deleted.
	data0, data1, err = m.Wait(id)
	c.Assert(data0, gc.IsNil)
	c.Assert(data1, gc.IsNil)
	c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`)
}

func (*suite) TestRendezvousDifferentPlaces(c *gc.C) {
	store := newFakeStore()
	m1, err := meeting.New(store, "localhost")
	c.Assert(err, gc.IsNil)
	defer m1.Close()
	m2, err := meeting.New(store, "localhost")
	c.Assert(err, gc.IsNil)
	defer m1.Close()
	m3, err := meeting.New(store, "localhost")
	c.Assert(err, gc.IsNil)
	defer m1.Close()

	// Create the rendezvous in m1.
	id, err := m1.NewRendezvous([]byte("first data"))
	c.Assert(err, gc.IsNil)
	c.Assert(id, gc.Not(gc.Equals), "")

	// Wait for the rendezvous in m2.
	waitDone := make(chan struct{})
	go func() {
		data0, data1, err := m2.Wait(id)
		c.Check(err, gc.IsNil)
		c.Check(string(data0), gc.Equals, "first data")
		c.Check(string(data1), gc.Equals, "second data")

		close(waitDone)
	}()
	err = m3.Done(id, []byte("second data"))
	c.Assert(err, gc.IsNil)

	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		c.Errorf("timed out waiting for rendezvous")
	}

	// Check that item has now been deleted.
	data0, data1, err := m3.Wait(id)
	c.Assert(data0, gc.IsNil)
	c.Assert(data1, gc.IsNil)
	c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`)
}

func (*suite) TestPutFailure(c *gc.C) {
	m, err := meeting.New(putErrorStore{}, "localhost")
	c.Assert(err, gc.IsNil)
	defer m.Close()
	id, err := m.NewRendezvous([]byte("x"))
	c.Assert(err, gc.ErrorMatches, "cannot create entry for rendezvous: put error")
	c.Assert(id, gc.Equals, "")
	c.Assert(meeting.ItemCount(m), gc.Equals, 0)
}

type putErrorStore struct {
	meeting.Store
}

func (putErrorStore) Put(id, address string) error {
	return errgo.Newf("put error")
}

type fakeStore struct {
	mu      sync.Mutex
	entries map[string]string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		entries: make(map[string]string),
	}
}

// Put implements Store.Put.
func (s fakeStore) Put(id, address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[id] = address
	return nil
}

// Get implements Store.Get.
func (s fakeStore) Get(id string) (address string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	addr, ok := s.entries[id]
	if !ok {
		return "", errgo.Newf("rendezvous %q not found", id)
	}
	return addr, nil
}

// Remove implements Store.Remove.
func (s fakeStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, id)
	return nil
}

// RemoveOld implements Store.RemoveOld.
func (s fakeStore) RemoveOld(address string, olderThan time.Time) (ids []string, err error) {
	return nil, errgo.Newf("RemoveOld not implemented")
}
