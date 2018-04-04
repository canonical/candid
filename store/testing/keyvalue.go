// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package testing

import (
	"time"

	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/store"
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
}

func (s *KeyValueSuite) TestGetNotFound(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	_, err = kv.Get(ctx, "test-not-there-key")
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, "key test-not-there-key not found")
}

func (s *KeyValueSuite) TestAdd(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	err = kv.Add(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	result, err := kv.Get(ctx, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(result), gc.Equals, "test-value")
}

func (s *KeyValueSuite) TestAddDuplicate(c *gc.C) {
	ctx := context.Background()
	kv, err := s.Store.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	err = kv.Add(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	err = kv.Add(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrDuplicateKey)
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

	err = kv1.Add(ctx1, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	err = kv2.Add(ctx2, "test-key", []byte("test-value-2"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	v, err := kv1.Get(ctx1, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(v), gc.Equals, "test-value")
}
