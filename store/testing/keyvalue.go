// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package testing

import (
	"time"

	"github.com/juju/simplekv"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/store"
)

// KeyValueSuite contains a set of tests for KeyValueStore implementations. The
// Store parameter need to be set before calling SetUpTest.
type KeyValueSuite struct {
	Store store.ProviderDataStore
}

func (s *KeyValueSuite) SetUpSuite(c *gc.C) {}

func (s *KeyValueSuite) TearDownSuite(c *gc.C) {}

func (s *KeyValueSuite) SetUpTest(c *gc.C) {}

func (s *KeyValueSuite) TearDownTest(c *gc.C) {}

func (s *KeyValueSuite) TestSet(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	result, err := kv.Get(ctx, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(result), gc.Equals, "test-value")

	// Try again with an existing record, which might trigger different behavior.
	err = kv.Set(ctx, "test-key", []byte("test-value-2"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	result, err = kv.Get(ctx, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(result), gc.Equals, "test-value-2")
}

func (s *KeyValueSuite) TestGetNotFound(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	_, err = kv.Get(ctx, "test-not-there-key")
	c.Assert(errgo.Cause(err), gc.Equals, simplekv.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, "key test-not-there-key not found")
}

func (s *KeyValueSuite) TestSetKeyOnce(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	err = simplekv.SetKeyOnce(ctx, kv, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	result, err := kv.Get(ctx, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(result), gc.Equals, "test-value")
}

func (s *KeyValueSuite) TestSetKeyOnceDuplicate(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	err = simplekv.SetKeyOnce(ctx, kv, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	err = simplekv.SetKeyOnce(ctx, kv, "test-key", []byte("test-value"), time.Time{})
	c.Assert(errgo.Cause(err), gc.Equals, simplekv.ErrDuplicateKey)
	c.Assert(err, gc.ErrorMatches, "key test-key already exists")
}

func (s *KeyValueSuite) TestTwoStoresForTheSameIDPCommunicate(c *gc.C) {
	ctx := context.Background()
	kv1, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	kv2, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx1, close := kv1.Context(ctx)
	defer close()
	ctx2, close := kv2.Context(ctx)
	defer close()

	err = kv1.Set(ctx1, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	v, err := kv2.Get(ctx2, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(v), gc.Equals, "test-value")
}

func (s *KeyValueSuite) TestTwoStoresForDifferentIDPsAreIndependent(c *gc.C) {
	ctx := context.Background()
	kv1, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	kv2, err := s.Store.KeyValueStore(ctx, "test2")
	c.Assert(err, gc.Equals, nil)
	ctx1, close := kv1.Context(ctx)
	defer close()
	ctx2, close := kv2.Context(ctx)
	defer close()

	err = simplekv.SetKeyOnce(ctx1, kv1, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	err = simplekv.SetKeyOnce(ctx2, kv2, "test-key", []byte("test-value-2"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	v, err := kv1.Get(ctx1, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(v), gc.Equals, "test-value")
}

func (s *KeyValueSuite) TestUpdateSuccessWithPreexistingKey(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(string(oldVal), gc.Equals, "test-value")
		return []byte("test-value-2"), nil
	})
	c.Assert(err, gc.Equals, nil)

	val, err := kv.Get(ctx, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(val), gc.Equals, "test-value-2")
}

func (s *KeyValueSuite) TestUpdateSuccessWithoutPreexistingKey(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(oldVal, gc.IsNil)
		return []byte("test-value"), nil
	})
	c.Assert(err, gc.Equals, nil)

	val, err := kv.Get(ctx, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(val), gc.Equals, "test-value")
}

func (s *KeyValueSuite) TestUpdateConcurrent(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)

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
				c.Check(err, gc.Equals, nil)
			}
			done <- struct{}{}
		}()
	}
	<-done
	<-done
	val, err := kv.Get(ctx, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(val, gc.HasLen, 1)
	c.Assert(int(val[0]), gc.Equals, N*2)
}

func (s *KeyValueSuite) TestUpdateErrorWithExistingKey(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)

	testErr := errgo.Newf("test error")

	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(string(oldVal), gc.Equals, "test-value")
		return nil, testErr
	})
	c.Check(errgo.Cause(err), gc.Equals, testErr)

}

func (s *KeyValueSuite) TestUpdateErrorWithNonExistentKey(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)

	testErr := errgo.Newf("test error")

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(oldVal, gc.IsNil)
		return nil, testErr
	})
	c.Check(errgo.Cause(err), gc.Equals, testErr)

}

func (s *KeyValueSuite) TestSetNilUpdatesAsNonNil(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)

	err = kv.Set(ctx, "test-key", nil, time.Time{})
	c.Assert(err, gc.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Assert(oldVal, gc.DeepEquals, []byte{})
		return nil, nil
	})
	c.Assert(err, gc.Equals, nil)
}

func (s *KeyValueSuite) TestUpdateReturnNilThenUpdatesAsNonNil(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)

	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(string(oldVal), gc.Equals, "test-value")
		return nil, nil
	})
	c.Assert(err, gc.Equals, nil)

	err = kv.Update(ctx, "test-key", time.Time{}, func(oldVal []byte) ([]byte, error) {
		c.Check(oldVal, gc.NotNil)
		c.Assert(oldVal, gc.DeepEquals, []byte{})
		return nil, nil
	})
	c.Assert(err, gc.Equals, nil)
}
