// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package storetest

import (
	"context"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/juju/simplekv"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/store"
)

type keyValueSuite struct {
	newStore func(c *qt.C) store.ProviderDataStore
	Store    store.ProviderDataStore
}

func TestKeyValueStore(c *qt.C, newStore func(c *qt.C) store.ProviderDataStore) {
	qtsuite.Run(c, &keyValueSuite{
		newStore: newStore,
	})
}

func (s *keyValueSuite) Init(c *qt.C) {
	s.Store = s.newStore(c)
}

func (s *keyValueSuite) TestSet(c *qt.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, qt.Equals, nil)

	result, err := kv.Get(ctx, "test-key")
	c.Assert(err, qt.Equals, nil)
	c.Assert(string(result), qt.Equals, "test-value")

	// Try again with an existing record, which might trigger different behavior.
	err = kv.Set(ctx, "test-key", []byte("test-value-2"), time.Time{})
	c.Assert(err, qt.Equals, nil)

	result, err = kv.Get(ctx, "test-key")
	c.Assert(err, qt.Equals, nil)
	c.Assert(string(result), qt.Equals, "test-value-2")
}

func (s *keyValueSuite) TestGetNotFound(c *qt.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	_, err = kv.Get(ctx, "test-not-there-key")
	c.Assert(errgo.Cause(err), qt.Equals, simplekv.ErrNotFound)
	c.Assert(err, qt.ErrorMatches, "key test-not-there-key not found")
}

func (s *keyValueSuite) TestSetKeyOnce(c *qt.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	err = simplekv.SetKeyOnce(ctx, kv, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, qt.Equals, nil)

	result, err := kv.Get(ctx, "test-key")
	c.Assert(err, qt.Equals, nil)
	c.Assert(string(result), qt.Equals, "test-value")
}

func (s *keyValueSuite) TestSetKeyOnceDuplicate(c *qt.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	err = simplekv.SetKeyOnce(ctx, kv, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, qt.Equals, nil)

	err = simplekv.SetKeyOnce(ctx, kv, "test-key", []byte("test-value"), time.Time{})
	c.Assert(errgo.Cause(err), qt.Equals, simplekv.ErrDuplicateKey)
	c.Assert(err, qt.ErrorMatches, "key test-key already exists")
}

func (s *keyValueSuite) TestTwoStoresForTheSameIDPCommunicate(c *qt.C) {
	ctx := context.Background()
	kv1, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	kv2, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	ctx1, close := kv1.Context(ctx)
	defer close()
	ctx2, close := kv2.Context(ctx)
	defer close()

	err = kv1.Set(ctx1, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, qt.Equals, nil)

	v, err := kv2.Get(ctx2, "test-key")
	c.Assert(err, qt.Equals, nil)
	c.Assert(string(v), qt.Equals, "test-value")
}

func (s *keyValueSuite) TestTwoStoresForDifferentIDPsAreIndependent(c *qt.C) {
	ctx := context.Background()
	kv1, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	kv2, err := s.Store.KeyValueStore(ctx, "test2")
	c.Assert(err, qt.Equals, nil)
	ctx1, close := kv1.Context(ctx)
	defer close()
	ctx2, close := kv2.Context(ctx)
	defer close()

	err = simplekv.SetKeyOnce(ctx1, kv1, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, qt.Equals, nil)

	err = simplekv.SetKeyOnce(ctx2, kv2, "test-key", []byte("test-value-2"), time.Time{})
	c.Assert(err, qt.Equals, nil)

	v, err := kv1.Get(ctx1, "test-key")
	c.Assert(err, qt.Equals, nil)
	c.Assert(string(v), qt.Equals, "test-value")
}

func (s *keyValueSuite) TestUpdateSuccessWithPreexistingKey(c *qt.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, qt.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(string(oldVal), qt.Equals, "test-value")
		return []byte("test-value-2"), nil
	})
	c.Assert(err, qt.Equals, nil)

	val, err := kv.Get(ctx, "test-key")
	c.Assert(err, qt.Equals, nil)
	c.Assert(string(val), qt.Equals, "test-value-2")
}

func (s *keyValueSuite) TestUpdateSuccessWithoutPreexistingKey(c *qt.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(oldVal, qt.IsNil)
		return []byte("test-value"), nil
	})
	c.Assert(err, qt.Equals, nil)

	val, err := kv.Get(ctx, "test-key")
	c.Assert(err, qt.Equals, nil)
	c.Assert(string(val), qt.Equals, "test-value")
}

func (s *keyValueSuite) TestUpdateConcurrent(c *qt.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)

	const N = 100
	done := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			for j := 0; j < N; j++ {
				err := kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
					time.Sleep(time.Millisecond)
					if oldVal == nil {
						return []byte{1}, nil
					}
					return []byte{oldVal[0] + 1}, nil
				})
				c.Check(err, qt.Equals, nil)
			}
			done <- struct{}{}
		}()
	}
	<-done
	<-done
	val, err := kv.Get(ctx, "test-key")
	c.Assert(err, qt.Equals, nil)
	c.Assert(val, qt.HasLen, 1)
	c.Assert(int(val[0]), qt.Equals, N*2)
}

func (s *keyValueSuite) TestUpdateErrorWithExistingKey(c *qt.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)

	testErr := errgo.Newf("test error")

	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, qt.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(string(oldVal), qt.Equals, "test-value")
		return nil, testErr
	})
	c.Check(errgo.Cause(err), qt.Equals, testErr)
}

func (s *keyValueSuite) TestUpdateErrorWithNonExistentKey(c *qt.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)

	testErr := errgo.Newf("test error")

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(oldVal, qt.IsNil)
		return nil, testErr
	})
	c.Check(errgo.Cause(err), qt.Equals, testErr)

}

func (s *keyValueSuite) TestSetNilUpdatesAsNonNil(c *qt.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)

	err = kv.Set(ctx, "test-key", nil, time.Time{})
	c.Assert(err, qt.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Assert(oldVal, qt.DeepEquals, []byte{})
		return nil, nil
	})
	c.Assert(err, qt.Equals, nil)
}

func (s *keyValueSuite) TestUpdateReturnNilThenUpdatesAsNonNil(c *qt.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)

	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, qt.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(string(oldVal), qt.Equals, "test-value")
		return nil, nil
	})
	c.Assert(err, qt.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(oldVal, qt.Not(qt.IsNil))
		c.Assert(oldVal, qt.DeepEquals, []byte{})
		return nil, nil
	})
	c.Assert(err, qt.Equals, nil)
}
