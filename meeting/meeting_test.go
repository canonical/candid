// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package meeting_test

import (
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juju/testing"
	"github.com/juju/utils/clock"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/meeting"
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

type nilMetrics struct{}

func (nilMetrics) RequestCompleted(startTime time.Time) {}
func (nilMetrics) RequestsExpired(count int)            {}

func (s *suite) TestRendezvousWaitBeforeDone(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	count := int32(0)
	store := newFakeStore(&count, s.clock)
	m, err := meeting.NewPlace(meeting.Params{
		Store:      store,
		ListenAddr: "localhost",
		DisableGC:  true,
	})
	c.Assert(err, gc.IsNil)
	defer m.Close()

	ctx := context.Background()

	id, err := newId()
	c.Assert(err, gc.IsNil)
	err = m.NewRendezvous(ctx, id, []byte("first data"))
	c.Assert(id, gc.Not(gc.Equals), "")

	waitDone := make(chan struct{})
	go func() {
		data0, data1, err := m.Wait(ctx, id)
		c.Check(err, gc.IsNil)
		c.Check(string(data0), gc.Equals, "first data")
		c.Check(string(data1), gc.Equals, "second data")

		close(waitDone)
	}()

	s.clock.Advance(10 * time.Millisecond)
	err = m.Done(ctx, id, []byte("second data"))
	c.Assert(err, gc.IsNil)
	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		c.Errorf("timed out waiting for rendezvous")
	}

	// Check that item has now been deleted.
	data0, data1, err := m.Wait(ctx, id)
	c.Assert(data0, gc.IsNil)
	c.Assert(data1, gc.IsNil)
	c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`)

	c.Assert(atomic.LoadInt32(&count), gc.Equals, int32(0))
}

func (s *suite) TestRendezvousDoneBeforeWait(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	count := int32(0)
	store := newFakeStore(&count, s.clock)
	p, err := meeting.NewPlace(meeting.Params{
		Store:      store,
		ListenAddr: "localhost",
		DisableGC:  true,
	})
	c.Assert(err, gc.IsNil)
	defer p.Close()

	ctx := context.Background()

	id, err := newId()
	c.Assert(err, gc.IsNil)
	err = p.NewRendezvous(ctx, id, []byte("first data"))
	c.Assert(err, gc.IsNil)
	c.Assert(id, gc.Not(gc.Equals), "")

	err = p.Done(ctx, id, []byte("second data"))
	c.Assert(err, gc.IsNil)

	err = p.Done(ctx, id, []byte("other second data"))
	c.Assert(err, gc.ErrorMatches, `.*rendezvous ".*" done twice`)

	data0, data1, err := p.Wait(ctx, id)
	c.Assert(err, gc.IsNil)
	c.Assert(string(data0), gc.Equals, "first data")
	c.Assert(string(data1), gc.Equals, "second data")

	// Check that item has now been deleted.
	data0, data1, err = p.Wait(ctx, id)
	c.Assert(data0, gc.IsNil)
	c.Assert(data1, gc.IsNil)
	c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`)

	c.Assert(atomic.LoadInt32(&count), gc.Equals, int32(0))
}

func (s *suite) TestRendezvousDifferentPlaces(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	count := int32(0)
	store := newFakeStore(&count, s.clock)
	m1, err := meeting.NewPlace(meeting.Params{
		Store:      store,
		ListenAddr: "localhost",
		DisableGC:  true,
	})
	c.Assert(err, gc.IsNil)
	defer m1.Close()
	m2, err := meeting.NewPlace(meeting.Params{
		Store:      store,
		ListenAddr: "localhost",
	})
	c.Assert(err, gc.IsNil)
	defer m2.Close()
	m3, err := meeting.NewPlace(meeting.Params{
		Store:      store,
		ListenAddr: "localhost",
	})
	c.Assert(err, gc.IsNil)
	defer m3.Close()

	ctx := context.Background()

	// Create the rendezvous in m1.
	id, err := newId()
	c.Assert(err, gc.IsNil)
	err = m1.NewRendezvous(ctx, id, []byte("first data"))
	c.Assert(err, gc.IsNil)
	c.Assert(id, gc.Not(gc.Equals), "")

	// Wait for the rendezvous in m2.
	waitDone := make(chan struct{})
	go func() {
		data0, data1, err := m2.Wait(ctx, id)
		c.Check(err, gc.IsNil)
		c.Check(string(data0), gc.Equals, "first data")
		c.Check(string(data1), gc.Equals, "second data")

		close(waitDone)
	}()
	s.clock.Advance(10 * time.Millisecond)
	err = m3.Done(ctx, id, []byte("second data"))
	c.Assert(err, gc.IsNil)

	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		c.Errorf("timed out waiting for rendezvous")
	}

	// Check that item has now been deleted.
	data0, data1, err := m3.Wait(ctx, id)
	c.Assert(data0, gc.IsNil)
	c.Assert(data1, gc.IsNil)
	c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`)

	c.Assert(atomic.LoadInt32(&count), gc.Equals, int32(0))
}

func (s *suite) TestEntriesRemovedOnClose(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	store := newFakeStore(nil, s.clock)
	m1, err := meeting.NewPlace(meeting.Params{
		Store:      store,
		ListenAddr: "localhost",
	})
	c.Assert(err, gc.IsNil)
	m2, err := meeting.NewPlace(meeting.Params{
		Store:      store,
		ListenAddr: "localhost",
	})
	c.Assert(err, gc.IsNil)

	ctx := context.Background()

	for i := 0; i < 3; i++ {
		err := m1.NewRendezvous(ctx, fmt.Sprintf("1%04x", i), []byte("something"))
		c.Assert(err, gc.IsNil)
	}
	for i := 0; i < 5; i++ {
		err := m2.NewRendezvous(ctx, fmt.Sprintf("2%04x", i), []byte("something"))
		c.Assert(err, gc.IsNil)
	}
	m1.Close()
	c.Assert(meeting.ItemCount(m1), gc.Equals, 0)
	c.Assert(store.itemCount(), gc.Equals, 5)

	m2.Close()
	c.Assert(store.itemCount(), gc.Equals, 0)
}

func (s *suite) TestRunGCNotDying(c *gc.C) {
	const expiryDuration = time.Hour
	store := newFakeStore(nil, s.clock)
	m1, err := meeting.NewPlace(meeting.Params{
		Store:          store,
		ListenAddr:     "localhost",
		ExpiryDuration: expiryDuration,
		DisableGC:      true,
	})
	c.Assert(err, gc.IsNil)
	m2, err := meeting.NewPlace(meeting.Params{
		Store:          store,
		ListenAddr:     "localhost",
		ExpiryDuration: expiryDuration,
		DisableGC:      true,
	})
	c.Assert(err, gc.IsNil)

	ctx := context.Background()

	var ids1, ids2 []string
	now := time.Now()
	// Create four rendezvous using the both servers server,
	// one really old, two old and one newer.
	for _, d := range []time.Duration{
		*meeting.ReallyOldExpiryDuration + time.Millisecond,
		expiryDuration + time.Millisecond,
		expiryDuration + 2*time.Millisecond,
		expiryDuration / 2,
	} {
		id, err := newId()
		c.Assert(err, gc.IsNil)
		err = m1.NewRendezvous(ctx, id, []byte("something"))
		c.Assert(err, gc.IsNil)
		ids1 = append(ids1, id)
		store.setCreationTime(id, now.Add(-d))

		id, err = newId()
		c.Assert(err, gc.IsNil)
		err = m2.NewRendezvous(ctx, id, []byte("something"))
		c.Assert(err, gc.IsNil)
		ids2 = append(ids2, id)
		store.setCreationTime(id, now.Add(-d))
	}

	err = meeting.RunGC(m1, ctx, false, now)
	c.Assert(err, gc.IsNil)

	// All the expired ids on the server we ran the GC on should have
	// been collected.
	for i, id := range ids1[0:3] {
		err := m1.Done(ctx, id, nil)
		c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`, gc.Commentf("id %d", i))
	}
	// The unexpired one should still be around.
	err = m1.Done(ctx, ids1[3], nil)
	c.Assert(err, gc.IsNil)

	// The really old id on the other server should have been collected.
	err = m1.Done(ctx, ids2[0], nil)
	c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`)

	// All the others should still be around.
	for _, id := range ids2[1:] {
		err = m1.Done(ctx, id, nil)
		c.Assert(err, gc.IsNil)
	}
}

func (s *suite) TestPartialRemoveOldFailure(c *gc.C) {
	const expiryDuration = time.Hour

	// RemoveOld can fail with ids and an error. If it
	// does so, the database and the server should remain
	// consistent.
	store := partialRemoveStore{newFakeStore(nil, s.clock)}
	m, err := meeting.NewPlace(meeting.Params{
		Store:          store,
		ListenAddr:     "localhost",
		ExpiryDuration: expiryDuration,
		DisableGC:      true,
	})
	c.Assert(err, gc.IsNil)

	ctx := context.Background()

	now := time.Now()
	for _, d := range []time.Duration{
		expiryDuration + time.Millisecond,
		expiryDuration + 2*time.Millisecond,
		expiryDuration / 2,
	} {
		id, err := newId()
		c.Assert(err, gc.IsNil)
		err = m.NewRendezvous(ctx, id, []byte("something"))
		c.Assert(err, gc.IsNil)
		store.setCreationTime(id, now.Add(-d))
	}

	err = meeting.RunGC(m, ctx, false, now)
	c.Assert(err, gc.ErrorMatches, "cannot remove old entries: partial error")

	c.Assert(meeting.ItemCount(m), gc.Equals, 2)
	c.Assert(store.itemCount(), gc.Equals, 2)

	err = meeting.RunGC(m, ctx, false, now)
	c.Assert(err, gc.ErrorMatches, "cannot remove old entries: partial error")

	c.Assert(meeting.ItemCount(m), gc.Equals, 1)
	c.Assert(store.itemCount(), gc.Equals, 1)
}

type partialRemoveStore struct {
	*fakeStore
}

func (s partialRemoveStore) RemoveOld(ctx context.Context, addr string, olderThan time.Time) ([]string, error) {
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
	m, err := meeting.NewPlace(meeting.Params{
		Store:      store,
		ListenAddr: "localhost",
		DisableGC:  true,
	})
	c.Assert(err, gc.IsNil)
	defer m.Close()
	ctx := context.Background()
	id, err := newId()
	c.Assert(err, gc.IsNil)
	err = m.NewRendezvous(ctx, id, []byte("x"))
	c.Assert(err, gc.ErrorMatches, "cannot create entry for rendezvous: put error")
	c.Assert(meeting.ItemCount(m), gc.Equals, 0)
}

func (s *suite) TestWaitTimeout(c *gc.C) {
	ctx := context.Background()
	store := newFakeStore(nil, s.clock)
	s.PatchValue(&meeting.Clock, s.clock)
	params := meeting.Params{
		Store:          store,
		ListenAddr:     "localhost",
		DisableGC:      true,
		WaitTimeout:    time.Second,
		ExpiryDuration: 5 * time.Second,
	}
	m, err := meeting.NewPlace(params)
	c.Assert(err, gc.IsNil)

	t0 := s.clock.Now()

	id, err := newId()
	c.Assert(err, gc.IsNil)
	err = m.NewRendezvous(ctx, id, nil)
	c.Assert(err, gc.Equals, nil)
	done := make(chan struct{})
	go func() {
		c.Logf("starting wait %q", id)
		_, _, err := m.Wait(ctx, id)
		c.Check(err, gc.ErrorMatches, "rendezvous wait timed out")
		done <- struct{}{}
	}()
	err = s.clock.WaitAdvance(params.WaitTimeout+1, time.Second, 1)
	c.Assert(err, gc.Equals, nil)
	select {
	case <-done:
	case <-time.After(time.Second):
		c.Fatalf("timed out waiting for Wait to time out")
	}

	// Try again. The item shouldn't have been removed, so we should be
	// able to repeat the request.
	go func() {
		_, _, err := m.Wait(ctx, id)
		c.Check(err, gc.ErrorMatches, "rendezvous wait timed out")
		done <- struct{}{}
	}()
	err = s.clock.WaitAdvance(params.WaitTimeout+1, time.Second, 1)
	c.Assert(err, gc.Equals, nil)
	select {
	case <-done:
	case <-time.After(time.Second):
		c.Fatalf("timed out waiting for Wait to time out")
	}

	c.Logf("after second wait, now: %v", s.clock.Now())
	// When the actual expiry deadline passes while we're waiting,
	// we should return when that happens.
	// Advance the clock to just before the expiry duration.
	expiryDeadline := t0.Add(params.ExpiryDuration)
	c.Logf("expiry deadline %v", expiryDeadline)

	s.clock.Advance(expiryDeadline.Add(-time.Millisecond).Sub(s.clock.Now()))

	go func() {
		_, _, err := m.Wait(ctx, id)
		c.Check(err, gc.ErrorMatches, "rendezvous expired after 5s")
		done <- struct{}{}
	}()
	waitDuration := expiryDeadline.Add(1).Sub(s.clock.Now())
	c.Logf("final wait from %v: %v", s.clock.Now(), waitDuration)
	err = s.clock.WaitAdvance(expiryDeadline.Add(1).Sub(s.clock.Now()), time.Second, 1)
	c.Assert(err, gc.Equals, nil)
	c.Logf("final time %v", s.clock.Now())

	select {
	case <-done:
	case <-time.After(time.Second):
		c.Fatalf("timed out waiting for Wait to time out")
	}
}

func (s *suite) TestRequestCompletedCalled(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	store := newFakeStore(nil, s.clock)
	tm := newTestMetrics()
	m, err := meeting.NewPlace(meeting.Params{
		Store:      store,
		Metrics:    tm,
		ListenAddr: "localhost",
	})
	c.Assert(err, gc.IsNil)
	defer m.Close()

	ctx := context.Background()

	id, err := newId()
	c.Assert(err, gc.IsNil)
	err = m.NewRendezvous(ctx, id, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(id, gc.Not(gc.Equals), "")

	waitDone := make(chan struct{})
	go func() {
		_, _, err := m.Wait(ctx, id)
		c.Check(err, gc.IsNil)
		c.Check(tm.completedCallCount, gc.Equals, 1)

		close(waitDone)
	}()

	s.clock.Advance(10 * time.Millisecond)
	err = m.Done(ctx, id, nil)
	c.Assert(err, gc.IsNil)
	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		c.Errorf("timed out waiting for rendezvous")
	}

	// Check that item has now been deleted.
	_, _, err = m.Wait(ctx, id)
	c.Assert(err, gc.ErrorMatches, `rendezvous ".*" not found`)
}

func (s *suite) TestRequestsExpiredCalled(c *gc.C) {
	s.PatchValue(&meeting.Clock, s.clock)
	store := newFakeStore(nil, s.clock)
	tm := newTestMetrics()
	m, err := meeting.NewPlace(meeting.Params{
		Store:      store,
		Metrics:    tm,
		ListenAddr: "localhost",
	})
	c.Assert(err, gc.IsNil)

	ctx := context.Background()

	for i := 0; i < 3; i++ {
		err := m.NewRendezvous(ctx, fmt.Sprintf("%04x", i), nil)
		c.Assert(err, gc.IsNil)
	}
	m.Close()
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

func (putErrorStore) Put(_ context.Context, id, address string) error {
	return errgo.Newf("put error")
}

func (putErrorStore) RemoveOld(context.Context, string, time.Time) ([]string, error) {
	return nil, nil
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

// Context implements Store.Context.
func (s *fakeStore) Context(ctx context.Context) (_ context.Context, close func()) {
	atomic.AddInt32(s.count, 1)
	return ctx, func() { atomic.AddInt32(s.count, -1) }
}

// Put implements Store.Put.
func (s *fakeStore) Put(_ context.Context, id, addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[id] = &fakeStoreEntry{
		addr:         addr,
		creationTime: s.clock.Now(),
	}
	return nil
}

// Get implements Store.Get.
func (s *fakeStore) Get(_ context.Context, id string) (address string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry := s.entries[id]; entry != nil {
		return entry.addr, nil
	}
	return "", errgo.Newf("rendezvous %q not found", id)
}

// Remove implements Store.Remove.
func (s *fakeStore) Remove(_ context.Context, id string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, id)
	return epoch, nil
}

// RemoveOld implements Store.RemoveOld.
func (s *fakeStore) RemoveOld(_ context.Context, addr string, olderThan time.Time) (ids []string, err error) {
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

func newId() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", errgo.Notef(err, "cannot read random id")
	}
	return fmt.Sprintf("%x", id[:]), nil
}
