// Copyright 2017 Canonical Ltd.

package mgostore_test

import (
	"time"

	"github.com/juju/testing"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/mgostore"
	"github.com/CanonicalLtd/blues-identity/store"
)

type kvSuite struct {
	testing.IsolatedMgoSuite
	db       *mgostore.Database
	idpStore store.IDPDataStore
}

var _ = gc.Suite(&kvSuite{})

func (s *kvSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.db, err = mgostore.NewDatabase(s.Session.DB("idm-test"))
	c.Assert(err, gc.Equals, nil)
	s.idpStore = s.db.IDPDataStore()
}

func (s *kvSuite) TearDownTest(c *gc.C) {
	s.db.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

func (s *kvSuite) TestSet(c *gc.C) {
	ctx := context.Background()
	kv, err := s.idpStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	result, err := kv.Get(ctx, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(result), gc.Equals, "test-value")
}

func (s *kvSuite) TestGetNotFound(c *gc.C) {
	ctx := context.Background()
	kv, err := s.idpStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	_, err = kv.Get(ctx, "test-not-there-key")
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, "key test-not-there-key not found")
}

func (s *kvSuite) TestAdd(c *gc.C) {
	ctx := context.Background()
	kv, err := s.idpStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	err = kv.Add(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	result, err := kv.Get(ctx, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(result), gc.Equals, "test-value")
}

func (s *kvSuite) TestAddDuplicate(c *gc.C) {
	ctx := context.Background()
	kv, err := s.idpStore.KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	err = kv.Add(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)

	err = kv.Add(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrDuplicateKey)
	c.Assert(err, gc.ErrorMatches, "key test-key already exists")
}
