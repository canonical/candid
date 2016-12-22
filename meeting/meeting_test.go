// Copyright 2014 Canonical Ltd.

package meeting_test

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/juju/testing"
	"github.com/juju/utils/clock"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/meeting"
)

type suite struct {
	testing.IsolationSuite
	// clock holds the mock clock used by the meeting package.
	clock *testing.Clock
}

var _ = gc.Suite(&suite{})

var epoch = parseTime("2016-01-01T12:00:00Z")

func (s *suite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	// Set up the clock mockery.
	s.clock = testing.NewClock(epoch)
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func fakeStoreGet(count *int32) (meeting.Store, error) {
	return newFakeStore(count, nil), nil
}

// storeGetter returns a function that always returns the given store.
// If count is non-nil, it will be atomically incremented each time
// the function is called.
func storeGetter(store meeting.Store, count *int32) func() meeting.Store {
	return func() meeting.Store {
		if count != nil {
			atomic.AddInt32(count, 1)
		}
		return store
	}
}

type nilMetrics struct{}

func (nilMetrics) RequestCompleted(startTime time.Time) {}
func (nilMetrics) RequestsExpired(count int)            {}

func (s *suite) TestRendezvousWaitBeforeDone(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	count := int32(0)
	store := newFakeStore(&count, s.clock)
	srv, err := meeting.NewServer(storeGetter(store, &count), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)
	defer srv.Close()

	m := srv.Place(store)
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

	s.clock.Advance(10 * time.Millisecond)
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

	c.Assert(count, gc.Equals, int32(0))
}

func (s *suite) TestRendezvousDoneBeforeWait(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	count := int32(0)
	store := newFakeStore(&count, s.clock)
	srv, err := meeting.NewServer(storeGetter(store, &count), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)
	defer srv.Close()

	m := srv.Place(store)

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

	// TODO this test sometimes fails with a count of 1.
	// e.g. http://ci-gce.theblues.io:8080/job/blues-identity/626/console
	c.Assert(count, gc.Equals, int32(0))
}

func (s *suite) TestRendezvousDifferentPlaces(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	count := int32(0)
	store := newFakeStore(&count, s.clock)
	srv1, err := meeting.NewServer(storeGetter(store, &count), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)
	defer srv1.Close()
	srv2, err := meeting.NewServer(storeGetter(store, &count), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)
	defer srv2.Close()
	srv3, err := meeting.NewServer(storeGetter(store, &count), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)
	defer srv3.Close()

	// Create the rendezvous in m1.
	m1 := srv1.Place(store)
	id, err := m1.NewRendezvous([]byte("first data"))
	c.Assert(err, gc.IsNil)
	c.Assert(id, gc.Not(gc.Equals), "")

	// Wait for the rendezvous in m2.
	waitDone := make(chan struct{})
	go func() {
		m2 := srv2.Place(store)
		data0, data1, err := m2.Wait(id)
		c.Check(err, gc.IsNil)
		c.Check(string(data0), gc.Equals, "first data")
		c.Check(string(data1), gc.Equals, "second data")

		close(waitDone)
	}()
	s.clock.Advance(10 * time.Millisecond)
	m3 := srv3.Place(store)
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

	c.Assert(count, gc.Equals, int32(0))
}

func (s *suite) TestEntriesRemovedOnClose(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	store := newFakeStore(nil, s.clock)
	srv1, err := meeting.NewServer(storeGetter(store, nil), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)
	srv2, err := meeting.NewServer(storeGetter(store, nil), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)

	m1 := srv1.Place(store)
	for i := 0; i < 3; i++ {
		_, err := m1.NewRendezvous([]byte("something"))
		c.Assert(err, gc.IsNil)
	}
	m2 := srv2.Place(store)
	for i := 0; i < 5; i++ {
		_, err := m2.NewRendezvous([]byte("something"))
		c.Assert(err, gc.IsNil)
	}
	srv1.Close()
	c.Assert(meeting.ItemCount(srv1), gc.Equals, 0)
	c.Assert(store.itemCount(), gc.Equals, 5)

	srv2.Close()
	c.Assert(store.itemCount(), gc.Equals, 0)
}

func (s *suite) TestRunGCNotDying(c *gc.C) {
	store := newFakeStore(nil, s.clock)
	srv1, err := meeting.NewServerNoGC(storeGetter(store, nil), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)
	srv2, err := meeting.NewServerNoGC(storeGetter(store, nil), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)

	m1 := srv1.Place(store)
	m2 := srv2.Place(store)

	var ids1, ids2 []string
	now := time.Now()
	// Create four rendezvous using the both servers server,
	// one really old, two old and one newer.
	for _, d := range []time.Duration{
		*meeting.ReallyOldExpiryDuration + time.Millisecond,
		*meeting.ExpiryDuration + time.Millisecond,
		*meeting.ExpiryDuration + 2*time.Millisecond,
		*meeting.ExpiryDuration / 2,
	} {
		id, err := m1.NewRendezvous([]byte("something"))
		c.Assert(err, gc.IsNil)
		ids1 = append(ids1, id)
		store.setCreationTime(id, now.Add(-d))

		id, err = m2.NewRendezvous([]byte("something"))
		c.Assert(err, gc.IsNil)
		ids2 = append(ids2, id)
		store.setCreationTime(id, now.Add(-d))
	}

	err = meeting.RunGC(srv1, false, now)
	c.Assert(err, gc.IsNil)

	// All the expired ids on the server we ran the GC on should have
	// been collected.
	for i, id := range ids1[0:3] {
		err := m1.Done(id, nil)
		c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`, gc.Commentf("id %d", i))
	}
	// The unexpired one should still be around.
	err = m1.Done(ids1[3], nil)
	c.Assert(err, gc.IsNil)

	// The really old id on the other server should have been collected.
	err = m1.Done(ids2[0], nil)
	c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`)

	// All the others should still be around.
	for _, id := range ids2[1:] {
		err = m1.Done(id, nil)
		c.Assert(err, gc.IsNil)
	}
}

func (s *suite) TestPartialRemoveOldFailure(c *gc.C) {
	// RemoveOld can fail with ids and an error. If it
	// does so, the database and the server should remain
	// consistent.
	store := partialRemoveStore{newFakeStore(nil, s.clock)}
	srv, err := meeting.NewServerNoGC(storeGetter(store, nil), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)
	m := srv.Place(store)

	now := time.Now()
	for _, d := range []time.Duration{
		*meeting.ExpiryDuration + time.Millisecond,
		*meeting.ExpiryDuration + 2*time.Millisecond,
		*meeting.ExpiryDuration / 2,
	} {
		id, err := m.NewRendezvous([]byte("something"))
		c.Assert(err, gc.IsNil)
		store.setCreationTime(id, now.Add(-d))
	}

	err = meeting.RunGC(srv, false, now)
	c.Assert(err, gc.ErrorMatches, "cannot remove old entries: partial error")

	c.Assert(meeting.ItemCount(srv), gc.Equals, 2)
	c.Assert(store.itemCount(), gc.Equals, 2)

	err = meeting.RunGC(srv, false, now)
	c.Assert(err, gc.ErrorMatches, "cannot remove old entries: partial error")

	c.Assert(meeting.ItemCount(srv), gc.Equals, 1)
	c.Assert(store.itemCount(), gc.Equals, 1)
}

type partialRemoveStore struct {
	*fakeStore
}

func (s partialRemoveStore) RemoveOld(addr string, olderThan time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, entry := range s.entries {
		if entry.creationTime.Before(olderThan) && (addr == "" || entry.addr == addr) {
			delete(s.entries, id)
			return []string{id}, errgo.New("partial error")
		}
	}
	return nil, nil
}

func (*suite) TestPutFailure(c *gc.C) {
	store := putErrorStore{}
	srv, err := meeting.NewServer(storeGetter(store, nil), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)
	defer srv.Close()
	m := srv.Place(store)
	id, err := m.NewRendezvous([]byte("x"))
	c.Assert(err, gc.ErrorMatches, "cannot create entry for rendezvous: put error")
	c.Assert(id, gc.Equals, "")
	c.Assert(meeting.ItemCount(srv), gc.Equals, 0)
}

func (s *suite) TestWaitTimeout(c *gc.C) {
	s.PatchValue(meeting.ExpiryDuration, 100*time.Millisecond)
	store := newFakeStore(nil, s.clock)
	srv, err := meeting.NewServerNoGC(storeGetter(store, nil), nilMetrics{}, "localhost")
	c.Assert(err, gc.IsNil)

	m := srv.Place(store)
	id, err := m.NewRendezvous(nil)
	c.Assert(err, gc.IsNil)
	_, _, err = m.Wait(id)
	c.Logf("err: %#v", err)
	c.Assert(err, gc.ErrorMatches, "rendezvous has expired after 100ms")
}

func (s *suite) TestRequestCompletedCalled(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	store := newFakeStore(nil, s.clock)
	tm := newTestMetrics()
	srv, err := meeting.NewServer(storeGetter(store, nil), tm, "localhost")
	c.Assert(err, gc.IsNil)
	defer srv.Close()

	m := srv.Place(store)
	id, err := m.NewRendezvous(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(id, gc.Not(gc.Equals), "")

	waitDone := make(chan struct{})
	go func() {
		_, _, err := m.Wait(id)
		c.Check(err, gc.IsNil)
		c.Check(tm.completedCallCount, gc.Equals, 1)

		close(waitDone)
	}()

	s.clock.Advance(10 * time.Millisecond)
	err = m.Done(id, nil)
	c.Assert(err, gc.IsNil)
	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		c.Errorf("timed out waiting for rendezvous")
	}

	// Check that item has now been deleted.
	_, _, err = m.Wait(id)
	c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`)
}

func (s *suite) TestRequestsExpiredCalled(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	store := newFakeStore(nil, s.clock)
	tm := newTestMetrics()
	srv, err := meeting.NewServer(storeGetter(store, nil), tm, "localhost")
	c.Assert(err, gc.IsNil)

	m := srv.Place(store)
	for i := 0; i < 3; i++ {
		_, err := m.NewRendezvous(nil)
		c.Assert(err, gc.IsNil)
	}
	srv.Close()
	c.Assert(tm.expiredCallCount, gc.Equals, 1)
	c.Assert(tm.expiredCallValues, gc.DeepEquals, []int{3})

}

type testMetrics struct {
	completedCallCount int
	expiredCallCount   int
	expiredCallValues  []int
}

func newTestMetrics() *testMetrics {
	return &testMetrics{
		expiredCallValues: []int{},
	}
}

func (m *testMetrics) RequestCompleted(startTime time.Time) {
	m.completedCallCount++
}

func (m *testMetrics) RequestsExpired(count int) {
	m.expiredCallCount++
	m.expiredCallValues = append(m.expiredCallValues, count)
}

type putErrorStore struct {
	meeting.Store
}

func (putErrorStore) Put(id, address string) error {
	return errgo.Newf("put error")
}

func (putErrorStore) RemoveOld(string, time.Time) ([]string, error) {
	return nil, nil
}

func (putErrorStore) Close() {
}

type fakeStore struct {
	clock   clock.Clock
	count   *int32
	mu      sync.Mutex
	entries map[string]*fakeStoreEntry
}

type fakeStoreEntry struct {
	addr         string
	creationTime time.Time
}

// newFakeStore returns an in memory store implementation.
// If count is non-nil, will atomically decrement it whenever the
// store is closed.
func newFakeStore(count *int32, clck clock.Clock) *fakeStore {
	if count == nil {
		count = new(int32)
	}
	if clck == nil {
		clck = clock.WallClock
	}
	return &fakeStore{
		clock:   clck,
		count:   count,
		entries: make(map[string]*fakeStoreEntry),
	}
}

func (s *fakeStore) itemCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *fakeStore) setCreationTime(id string, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[id].creationTime = t
}

// Put implements Store.Put.
func (s *fakeStore) Put(id, addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[id] = &fakeStoreEntry{
		addr:         addr,
		creationTime: s.clock.Now(),
	}
	return nil
}

// Get implements Store.Get.
func (s *fakeStore) Get(id string) (address string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry := s.entries[id]; entry != nil {
		return entry.addr, nil
	}
	return "", errgo.Newf("rendezvous %q not found", id)
}

// Remove implements Store.Remove.
func (s *fakeStore) Remove(id string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, id)
	return epoch, nil
}

// RemoveOld implements Store.RemoveOld.
func (s *fakeStore) RemoveOld(addr string, olderThan time.Time) (ids []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, entry := range s.entries {
		if entry.creationTime.Before(olderThan) && (addr == "" || entry.addr == addr) {
			delete(s.entries, id)
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// Close implements Store.Close.
func (s *fakeStore) Close() {
	atomic.AddInt32(s.count, -1)
}
