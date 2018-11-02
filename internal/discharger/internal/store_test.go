// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package internal_test

import (
	"time"

	"github.com/juju/simplekv"
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/candid/internal/candidtest"
	"github.com/CanonicalLtd/candid/internal/discharger/internal"
	"github.com/CanonicalLtd/candid/store"
)

type storeSuite struct {
	candidtest.StoreSuite
}

var _ = gc.Suite(&storeSuite{})

func (s *storeSuite) TestRoundTrip(c *gc.C) {
	ctx := context.Background()
	kv, err := s.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	store := internal.NewDischargeTokenStore(kv)
	dt := httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte("test-value"),
	}
	key, err := store.Put(ctx, &dt, time.Now().Add(time.Minute))
	c.Assert(err, gc.Equals, nil)
	dt1, err := store.Get(ctx, key)
	c.Assert(err, gc.Equals, nil)
	c.Assert(dt1, jc.DeepEquals, &dt)
}

func (s *storeSuite) TestPutCanceled(c *gc.C) {
	ctx := context.Background()
	kv, err := s.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	store := internal.NewDischargeTokenStore(withSet(kv, func(context.Context, string, []byte, time.Time) error {
		return context.Canceled
	}))
	dt := httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte("test-value"),
	}
	_, err = store.Put(ctx, &dt, time.Now().Add(time.Minute))
	c.Assert(err, gc.ErrorMatches, "context canceled")
	c.Assert(errgo.Cause(err), gc.Equals, context.Canceled)
}

func (s *storeSuite) TestPutDeadlineExceeded(c *gc.C) {
	ctx := context.Background()
	kv, err := s.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	store := internal.NewDischargeTokenStore(withSet(kv, func(context.Context, string, []byte, time.Time) error {
		return context.DeadlineExceeded
	}))
	dt := httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte("test-value"),
	}
	_, err = store.Put(ctx, &dt, time.Now().Add(time.Minute))
	c.Assert(err, gc.ErrorMatches, "context deadline exceeded")
	c.Assert(errgo.Cause(err), gc.Equals, context.DeadlineExceeded)
}

func (s *storeSuite) TestGetNotFound(c *gc.C) {
	ctx := context.Background()
	kv, err := s.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	st := internal.NewDischargeTokenStore(withGet(kv, func(context.Context, string) ([]byte, error) {
		return nil, simplekv.ErrNotFound
	}))
	_, err = st.Get(ctx, "")
	c.Assert(err, gc.ErrorMatches, "not found")
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
}

func (s *storeSuite) TestGetCanceled(c *gc.C) {
	ctx := context.Background()
	kv, err := s.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	st := internal.NewDischargeTokenStore(withGet(kv, func(context.Context, string) ([]byte, error) {
		return nil, context.Canceled
	}))
	_, err = st.Get(ctx, "")
	c.Assert(err, gc.ErrorMatches, "context canceled")
	c.Assert(errgo.Cause(err), gc.Equals, context.Canceled)
}

func (s *storeSuite) TestGetDeadlineExceeded(c *gc.C) {
	ctx := context.Background()
	kv, err := s.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	st := internal.NewDischargeTokenStore(withGet(kv, func(context.Context, string) ([]byte, error) {
		return nil, context.DeadlineExceeded
	}))
	_, err = st.Get(ctx, "")
	c.Assert(err, gc.ErrorMatches, "context deadline exceeded")
	c.Assert(errgo.Cause(err), gc.Equals, context.DeadlineExceeded)
}

func (s *storeSuite) TestGetInvalidJSON(c *gc.C) {
	ctx := context.Background()
	kv, err := s.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	st := internal.NewDischargeTokenStore(withGet(kv, func(context.Context, string) ([]byte, error) {
		return []byte("}"), nil
	}))
	_, err = st.Get(ctx, "")
	c.Assert(err, gc.ErrorMatches, "invalid character '}' looking for beginning of value")
}

func (s *storeSuite) TestExpiredEntry(c *gc.C) {
	ctx := context.Background()
	kv, err := s.ProviderDataStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	st := internal.NewDischargeTokenStore(kv)
	dt := httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte("test-value"),
	}
	key, err := st.Put(ctx, &dt, time.Now())
	c.Assert(err, gc.Equals, nil)
	_, err = st.Get(ctx, key)
	c.Assert(err, gc.ErrorMatches, `".*" not found`)
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
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
