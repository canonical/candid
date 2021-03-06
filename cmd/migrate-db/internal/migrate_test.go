// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package internal_test

import (
	"context"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v3/bakery"

	"github.com/canonical/candid/v2/cmd/migrate-db/internal"
	"github.com/canonical/candid/v2/store"
	"github.com/canonical/candid/v2/store/memstore"
)

var splitStoreSpecificationTests = []struct {
	spec       string
	expectType string
	expectAddr string
}{{
	spec:       "postgres:host=/var/run/postgresql",
	expectType: "postgres",
	expectAddr: "host=/var/run/postgresql",
}, {
	spec:       "legacy:",
	expectType: "legacy",
	expectAddr: "",
}, {
	spec:       "mgo",
	expectType: "mgo",
	expectAddr: "",
}, {
	spec:       ":something",
	expectType: "",
	expectAddr: "something",
}, {
	spec:       "",
	expectType: "",
	expectAddr: "",
}}

func TestSplitStoreSpecification(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	for i, test := range splitStoreSpecificationTests {
		c.Logf("%d. %s", i, test.spec)
		type_, addr := internal.SplitStoreSpecification(test.spec)
		c.Assert(type_, qt.Equals, test.expectType)
		c.Assert(addr, qt.Equals, test.expectAddr)
	}
}

func TestStoreSource(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	st := memstore.NewStore()
	ctx := context.Background()
	err := st.UpdateIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "1"),
		Username:   "test1",
	}, store.Update{
		store.Username: store.Set,
	})
	c.Assert(err, qt.IsNil)
	err = st.UpdateIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "2"),
		Username:   "test2",
	}, store.Update{
		store.Username: store.Set,
	})
	c.Assert(err, qt.IsNil)
	source := internal.NewStoreSource(ctx, st)
	usernames := make(map[string]struct{})
	for source.Next() {
		usernames[source.Identity().Username] = struct{}{}
	}
	c.Assert(source.Err(), qt.Equals, nil)
	c.Assert(usernames, qt.DeepEquals, map[string]struct{}{
		"test1": {},
		"test2": {},
	})
}

func TestStoreSourceEmpty(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	store := memstore.NewStore()
	source := internal.NewStoreSource(context.Background(), store)
	c.Assert(source.Next(), qt.Equals, false)
	c.Assert(source.Err(), qt.Equals, nil)
}

func TestStoreSourceError(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	testError := errgo.New("test error")
	source := internal.NewStoreSource(context.Background(), errorStore{testError})
	c.Assert(source.Next(), qt.Equals, false)
	c.Assert(source.Err(), qt.Equals, testError)
}

type errorStore struct {
	err error
}

func (s errorStore) Context(ctx context.Context) (context.Context, func()) {
	return ctx, func() {}
}

func (s errorStore) Identity(_ context.Context, _ *store.Identity) error {
	return s.err
}

func (s errorStore) FindIdentities(_ context.Context, _ *store.Identity, _ store.Filter, _ []store.Sort, _, _ int) ([]store.Identity, error) {
	return nil, s.err
}

func (s errorStore) UpdateIdentity(_ context.Context, _ *store.Identity, _ store.Update) error {
	return s.err
}

func (s errorStore) IdentityCounts(_ context.Context) (map[string]int, error) {
	return nil, s.err
}

func TestCopy(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	store1 := memstore.NewStore()
	ctx := context.Background()
	k1 := bakery.MustGenerateKey()
	identity1 := store.Identity{
		ProviderID:    store.MakeProviderIdentity("test", "1"),
		Username:      "test1",
		Name:          "Test User",
		Email:         "test1@example.com",
		Groups:        []string{"group1", "group2"},
		PublicKeys:    []bakery.PublicKey{k1.Public},
		LastLogin:     time.Now().Add(-1 * time.Minute),
		LastDischarge: time.Now().Add(-2 * time.Minute),
		ProviderInfo: map[string][]string{
			"p1": {"p1v1", "p1v2"},
		},
		ExtraInfo: map[string][]string{
			"e1": {"e1v1", "e1v2"},
		},
	}
	err := store1.UpdateIdentity(ctx, &identity1, store.Update{
		store.Username:      store.Set,
		store.Name:          store.Set,
		store.Email:         store.Set,
		store.Groups:        store.Set,
		store.PublicKeys:    store.Set,
		store.LastLogin:     store.Set,
		store.LastDischarge: store.Set,
		store.ProviderInfo:  store.Set,
		store.ExtraInfo:     store.Set,
	})
	c.Assert(err, qt.IsNil)

	identity2 := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "2"),
		Username:   "test2",
	}
	err = store1.UpdateIdentity(ctx, &identity2, store.Update{
		store.Username: store.Set,
	})
	c.Assert(err, qt.IsNil)

	store2 := memstore.NewStore()
	err = internal.Copy(ctx, store2, internal.NewStoreSource(ctx, store1))
	c.Assert(err, qt.IsNil)

	copiedIdentity1 := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "1"),
	}
	err = store2.Identity(ctx, &copiedIdentity1)
	c.Assert(err, qt.IsNil)
	normalize(&identity1)
	normalize(&copiedIdentity1)
	c.Assert(copiedIdentity1, qt.DeepEquals, identity1)

	copiedIdentity2 := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "2"),
	}
	err = store2.Identity(ctx, &copiedIdentity2)
	c.Assert(err, qt.IsNil)
	normalize(&identity2)
	normalize(&copiedIdentity2)
	c.Assert(copiedIdentity2, qt.DeepEquals, identity2)
}

func normalize(identity *store.Identity) {
	identity.ID = ""
	if len(identity.Groups) == 0 {
		identity.Groups = nil
	}
	if len(identity.PublicKeys) == 0 {
		identity.PublicKeys = nil
	}
	if len(identity.ProviderInfo) == 0 {
		identity.ProviderInfo = nil
	}
	if len(identity.ExtraInfo) == 0 {
		identity.ExtraInfo = nil
	}
}

func TestCopySrcError(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	store1 := errorStore{errgo.New("test error")}
	ctx := context.Background()

	store2 := memstore.NewStore()
	err := internal.Copy(ctx, store2, internal.NewStoreSource(ctx, store1))
	c.Assert(err, qt.ErrorMatches, "cannot read identities: test error")
}

func TestCopyDstError(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	store1 := memstore.NewStore()
	ctx := context.Background()
	k1 := bakery.MustGenerateKey()
	identity1 := store.Identity{
		ProviderID:    store.MakeProviderIdentity("test", "1"),
		Username:      "test1",
		Name:          "Test User",
		Email:         "test1@example.com",
		Groups:        []string{"group1", "group2"},
		PublicKeys:    []bakery.PublicKey{k1.Public},
		LastLogin:     time.Now().Add(-1 * time.Minute),
		LastDischarge: time.Now().Add(-2 * time.Minute),
		ProviderInfo: map[string][]string{
			"p1": {"p1v1", "p1v2"},
		},
		ExtraInfo: map[string][]string{
			"e1": {"e1v1", "e1v2"},
		},
	}
	err := store1.UpdateIdentity(ctx, &identity1, store.Update{
		store.Username:      store.Set,
		store.Name:          store.Set,
		store.Email:         store.Set,
		store.Groups:        store.Set,
		store.PublicKeys:    store.Set,
		store.LastLogin:     store.Set,
		store.LastDischarge: store.Set,
		store.ProviderInfo:  store.Set,
		store.ExtraInfo:     store.Set,
	})
	c.Assert(err, qt.IsNil)

	store2 := errorStore{errgo.New("test error")}
	err = internal.Copy(ctx, store2, internal.NewStoreSource(ctx, store1))
	c.Assert(err, qt.ErrorMatches, "some updates failed")
}
