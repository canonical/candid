package sqlstore_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	aclstore "github.com/juju/aclstore/v2"
	"github.com/juju/postgrestest"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/candid/meeting"
	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/sqlstore"
	"github.com/CanonicalLtd/candid/store/storetest"
)

func TestKeyValueStore(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	storetest.TestKeyValueStore(c, func(c *qt.C) store.ProviderDataStore {
		return newFixture(c).backend.ProviderDataStore()
	})
}

func TestStore(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	storetest.TestStore(c, func(c *qt.C) store.Store {
		return newFixture(c).backend.Store()
	})
}

func TestMeetingStore(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	storetest.TestMeetingStore(c, func(c *qt.C) meeting.Store {
		return newFixture(c).backend.MeetingStore()
	}, sqlstore.PutAtTime)
}

func TestACLStore(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	storetest.TestACLStore(c, func(c *qt.C) aclstore.ACLStore {
		return newFixture(c).backend.ACLStore()
	})
}

func TestUpdateIDNotFound(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	f := newFixture(c)

	err := f.backend.Store().UpdateIdentity(
		context.Background(),
		&store.Identity{
			ID:   "1000000",
			Name: "test-user",
		},
		store.Update{
			store.Name: store.Set,
		},
	)
	c.Assert(err, qt.ErrorMatches, `identity "1000000" not found`)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
}

func TestUpdateIDEmptyNotFound(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	f := newFixture(c)

	err := f.backend.Store().UpdateIdentity(
		context.Background(),
		&store.Identity{
			ID: "1000000",
		},
		store.Update{},
	)
	c.Assert(err, qt.ErrorMatches, `identity "1000000" not found`)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
}

func TestUpdateUsernameEmptyNotFound(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	f := newFixture(c)

	err := f.backend.Store().UpdateIdentity(
		context.Background(),
		&store.Identity{
			Username: "no-user",
		},
		store.Update{},
	)
	c.Assert(err, qt.ErrorMatches, `user no-user not found`)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
}

func TestUpdateProviderIDEmptyNotFound(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	f := newFixture(c)

	err := f.backend.Store().UpdateIdentity(
		context.Background(),
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("test", "no-user"),
		},
		store.Update{},
	)
	c.Assert(err, qt.ErrorMatches, `identity "test:no-user" not found`)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
}

func TestInitIdempotent(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	f := newFixture(c)

	testStore := f.backend.Store()

	var pk1 bakery.PublicKey
	id1 := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-1"),
		Username:   "test-1",
		Name:       "Test User",
		Email:      "test-1@example.com",
		PublicKeys: []bakery.PublicKey{pk1},
		ProviderInfo: map[string][]string{
			"pk1": {"pk1v1", "pk1v2"},
		},
		ExtraInfo: map[string][]string{
			"ek1": {"ek1v1", "ek1v2"},
		},
		Owner: store.MakeProviderIdentity("test", "test-0"),
	}
	err := testStore.UpdateIdentity(
		context.Background(),
		&id1,
		store.Update{
			store.Username:     store.Set,
			store.Name:         store.Set,
			store.Email:        store.Set,
			store.PublicKeys:   store.Set,
			store.ProviderInfo: store.Set,
			store.ExtraInfo:    store.Set,
			store.Owner:        store.Set,
		},
	)
	c.Assert(err, qt.Equals, nil)
	backend, err := sqlstore.NewBackend("postgres", f.pg.DB)
	c.Assert(err, qt.Equals, nil)
	id2 := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-1"),
	}
	err = backend.Store().Identity(context.Background(), &id2)
	c.Assert(err, qt.Equals, nil)
	c.Assert(id2, qt.DeepEquals, id1)
}

type fixture struct {
	backend store.Backend
	pg      *postgrestest.DB
}

func newFixture(c *qt.C) *fixture {
	pg, err := postgrestest.New()
	if errgo.Cause(err) == postgrestest.ErrDisabled {
		c.Skip(err.Error())
	}
	c.Assert(err, qt.Equals, nil)

	backend, err := sqlstore.NewBackend("postgres", pg.DB)
	c.Assert(err, qt.Equals, nil)
	// Note: closing backend also closes the db.
	c.Defer(backend.Close)

	return &fixture{
		pg:      pg,
		backend: backend,
	}
}
