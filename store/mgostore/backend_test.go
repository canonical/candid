package mgostore_test

import (
	"context"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/juju/mgotest"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/mgostore"
)

func TestNewBackend(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	db, err := mgotest.New()
	if errgo.Cause(err) == mgotest.ErrDisabled {
		c.Skip("mgotest disabled")
	}
	c.Assert(err, qt.Equals, nil)
	defer db.Close()
	// mgotest sets the SocketTimout to 1s. Restore it back to the
	// default value.
	db.Session.SetSocketTimeout(time.Minute)

	testdb := db.Database
	s := testdb.Session.Copy()
	testdb = testdb.With(s)
	backend, err := mgostore.NewBackend(testdb)
	c.Assert(err, qt.Equals, nil)
	c.Defer(backend.Close)
	s.Close()

	ctx := context.Background()
	_, err = backend.Store().FindIdentities(ctx, &store.Identity{}, store.Filter{}, nil, 0, 0)
	c.Assert(err, qt.Equals, nil)

	err = backend.ACLStore().CreateACL(ctx, "test", []string{"test"})
	c.Assert(err, qt.Equals, nil)
}
