// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package internal_test

import (
	"context"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/juju/simplekv"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/internal/discharger/internal"
	"github.com/canonical/candid/store"
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
	store := internal.NewDischargeTokenStore(kv)
	dt := httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte("test-value"),
	}
	key, err := store.Put(ctx, &dt, time.Now().Add(time.Minute))
	c.Assert(err, qt.IsNil)
	dt1, err := store.Get(ctx, key)
	c.Assert(err, qt.IsNil)
	c.Assert(dt1, qt.DeepEquals, &dt)
}

func (s *storeSuite) TestPutCanceled(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	store := internal.NewDischargeTokenStore(withSet(kv, func(context.Context, string, []byte, time.Time) error {
		return context.Canceled
	}))
	dt := httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte("test-value"),
	}
	_, err = store.Put(ctx, &dt, time.Now().Add(time.Minute))
	c.Assert(err, qt.ErrorMatches, "context canceled")
	c.Assert(errgo.Cause(err), qt.Equals, context.Canceled)
}

func (s *storeSuite) TestPutDeadlineExceeded(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	store := internal.NewDischargeTokenStore(withSet(kv, func(context.Context, string, []byte, time.Time) error {
		return context.DeadlineExceeded
	}))
	dt := httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte("test-value"),
	}
	_, err = store.Put(ctx, &dt, time.Now().Add(time.Minute))
	c.Assert(err, qt.ErrorMatches, "context deadline exceeded")
	c.Assert(errgo.Cause(err), qt.Equals, context.DeadlineExceeded)
}

func (s *storeSuite) TestGetNotFound(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	st := internal.NewDischargeTokenStore(withGet(kv, func(context.Context, string) ([]byte, error) {
		return nil, simplekv.ErrNotFound
	}))
	_, err = st.Get(ctx, "")
	c.Assert(err, qt.ErrorMatches, "not found")
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
}

func (s *storeSuite) TestGetCanceled(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	st := internal.NewDischargeTokenStore(withGet(kv, func(context.Context, string) ([]byte, error) {
		return nil, context.Canceled
	}))
	_, err = st.Get(ctx, "")
	c.Assert(err, qt.ErrorMatches, "context canceled")
	c.Assert(errgo.Cause(err), qt.Equals, context.Canceled)
}

func (s *storeSuite) TestGetDeadlineExceeded(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	st := internal.NewDischargeTokenStore(withGet(kv, func(context.Context, string) ([]byte, error) {
		return nil, context.DeadlineExceeded
	}))
	_, err = st.Get(ctx, "")
	c.Assert(err, qt.ErrorMatches, "context deadline exceeded")
	c.Assert(errgo.Cause(err), qt.Equals, context.DeadlineExceeded)
}

func (s *storeSuite) TestGetInvalidJSON(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	st := internal.NewDischargeTokenStore(withGet(kv, func(context.Context, string) ([]byte, error) {
		return []byte("}"), nil
	}))
	_, err = st.Get(ctx, "")
	c.Assert(err, qt.ErrorMatches, "invalid character '}' looking for beginning of value")
}

func (s *storeSuite) TestExpiredEntry(c *qt.C) {
	ctx := context.Background()
	kv, err := s.store.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)
	st := internal.NewDischargeTokenStore(kv)
	dt := httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte("test-value"),
	}
	key, err := st.Put(ctx, &dt, time.Now())
	c.Assert(err, qt.IsNil)
	_, err = st.Get(ctx, key)
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
