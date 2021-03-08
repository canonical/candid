// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package internal_test

import (
	"context"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juju/simplekv"
	errgo "gopkg.in/errgo.v1"

	"gopkg.in/canonical/candid.v2/internal/candidtest"
	"gopkg.in/canonical/candid.v2/internal/discharger/internal"
	"gopkg.in/canonical/candid.v2/store"
)

func TestStore(t *testing.T) {
	qtsuite.Run(qt.New(t), &storeSuite{})
}

type storeSuite struct {
	store *candidtest.Store
}

func (s *storeSuite) Init(c *qt.C) {
	s.store = candidtest.NewStore()
}

func (s *storeSuite) TestRoundTrip(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	st := internal.NewIdentityStore(kv, s.store.Store)
	id := store.Identity{
		ProviderID: "test:test",
		Username:   "test",
		Name:       "Test User",
		Email:      "test@example.com",
	}
	err = s.store.Store.UpdateIdentity(ctx, &id, store.Update{
		store.Username: store.Set,
		store.Name:     store.Set,
		store.Email:    store.Set,
	})
	c.Assert(err, qt.IsNil)

	key, err := st.Put(ctx, &id, time.Now().Add(time.Minute))
	c.Assert(err, qt.IsNil)
	var id2 store.Identity
	err = st.Get(ctx, key, &id2)
	c.Assert(err, qt.IsNil)
	c.Check(id2, qt.CmpEquals(cmpopts.EquateEmpty()), id)
}

func (s *storeSuite) TestPutCanceled(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	kv = withSet(kv, func(context.Context, string, []byte, time.Time) error {
		return context.Canceled
	})
	st := internal.NewIdentityStore(kv, s.store.Store)
	id := store.Identity{
		ProviderID: "test:test",
		Username:   "test",
		Name:       "Test User",
		Email:      "test@example.com",
	}
	err = s.store.Store.UpdateIdentity(ctx, &id, store.Update{
		store.Username: store.Set,
		store.Name:     store.Set,
		store.Email:    store.Set,
	})
	c.Assert(err, qt.IsNil)

	_, err = st.Put(ctx, &id, time.Now().Add(time.Minute))
	c.Assert(err, qt.ErrorMatches, "context canceled")
	c.Assert(errgo.Cause(err), qt.Equals, context.Canceled)
}

func (s *storeSuite) TestPutDeadlineExceeded(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	kv = withSet(kv, func(context.Context, string, []byte, time.Time) error {
		return context.DeadlineExceeded
	})
	st := internal.NewIdentityStore(kv, s.store.Store)
	id := store.Identity{
		ProviderID: "test:test",
		Username:   "test",
		Name:       "Test User",
		Email:      "test@example.com",
	}
	err = s.store.Store.UpdateIdentity(ctx, &id, store.Update{
		store.Username: store.Set,
		store.Name:     store.Set,
		store.Email:    store.Set,
	})
	c.Assert(err, qt.IsNil)

	_, err = st.Put(ctx, &id, time.Now().Add(time.Minute))
	c.Assert(err, qt.ErrorMatches, "context deadline exceeded")
	c.Assert(errgo.Cause(err), qt.Equals, context.DeadlineExceeded)
}

func (s *storeSuite) TestGetNotFound(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	kv = withGet(kv, func(context.Context, string) ([]byte, error) {
		return nil, simplekv.ErrNotFound
	})
	st := internal.NewIdentityStore(kv, s.store.Store)
	err = st.Get(ctx, "", nil)
	c.Assert(err, qt.ErrorMatches, "not found")
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
}

func (s *storeSuite) TestGetCanceled(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	kv = withGet(kv, func(context.Context, string) ([]byte, error) {
		return nil, context.Canceled
	})
	st := internal.NewIdentityStore(kv, s.store.Store)
	err = st.Get(ctx, "", nil)
	c.Assert(err, qt.ErrorMatches, "context canceled")
	c.Assert(errgo.Cause(err), qt.Equals, context.Canceled)
}

func (s *storeSuite) TestGetDeadlineExceeded(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	kv = withGet(kv, func(context.Context, string) ([]byte, error) {
		return nil, context.DeadlineExceeded
	})
	st := internal.NewIdentityStore(kv, s.store.Store)
	err = st.Get(ctx, "", nil)
	c.Assert(err, qt.ErrorMatches, "context deadline exceeded")
	c.Assert(errgo.Cause(err), qt.Equals, context.DeadlineExceeded)
}

func (s *storeSuite) TestGetInvalidJSON(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	kv = withGet(kv, func(context.Context, string) ([]byte, error) {
		return []byte("}"), nil
	})
	st := internal.NewIdentityStore(kv, s.store.Store)
	err = st.Get(ctx, "", nil)
	c.Assert(err, qt.ErrorMatches, "invalid character '}' looking for beginning of value")
}

func (s *storeSuite) TestExpiredEntry(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	st := internal.NewIdentityStore(kv, s.store.Store)
	id := store.Identity{
		ProviderID: "test:test",
		Username:   "test",
		Name:       "Test User",
		Email:      "test@example.com",
	}
	err = s.store.Store.UpdateIdentity(ctx, &id, store.Update{
		store.Username: store.Set,
		store.Name:     store.Set,
		store.Email:    store.Set,
	})
	c.Assert(err, qt.IsNil)

	key, err := st.Put(ctx, &id, time.Now())
	c.Assert(err, qt.IsNil)
	err = st.Get(ctx, key, nil)
	c.Assert(err, qt.ErrorMatches, `".*" not found`)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
}

func (s *storeSuite) TestIdentityNotInStore(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	st := internal.NewIdentityStore(kv, s.store.Store)
	id := store.Identity{
		ProviderID: "test:test",
		Username:   "test",
		Name:       "Test User",
		Email:      "test@example.com",
	}

	key, err := st.Put(ctx, &id, time.Now().Add(time.Minute))
	c.Assert(err, qt.IsNil)
	var id2 store.Identity
	err = st.Get(ctx, key, &id2)
	c.Assert(err, qt.ErrorMatches, `".*" not found`)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
}

type testGetStore struct {
	simplekv.Store
	f func(context.Context, string) ([]byte, error)
}

func (s testGetStore) Get(ctx context.Context, key string) ([]byte, error) {
	return s.f(ctx, key)
}

func withGet(store simplekv.Store, get func(context.Context, string) ([]byte, error)) simplekv.Store {
	return testGetStore{
		Store: store,
		f:     get,
	}
}

type testSetStore struct {
	simplekv.Store
	f func(context.Context, string, []byte, time.Time) error
}

func (s testSetStore) Set(ctx context.Context, key string, value []byte, expire time.Time) error {
	return s.f(ctx, key, value, expire)
}

func withSet(store simplekv.Store, set func(context.Context, string, []byte, time.Time) error) simplekv.Store {
	return testSetStore{
		Store: store,
		f:     set,
	}
}
