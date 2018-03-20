// Copyright 2018 Canonical Ltd.

package internal_test

import (
	"time"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/blues-identity/cmd/migrate-db/internal"
	"github.com/CanonicalLtd/blues-identity/memstore"
	"github.com/CanonicalLtd/blues-identity/store"
)

type migrateSuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(&migrateSuite{})

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

func (s *migrateSuite) TestSplitStoreSpecification(c *gc.C) {
	for i, test := range splitStoreSpecificationTests {
		c.Logf("%d. %s", i, test.spec)
		type_, addr := internal.SplitStoreSpecification(test.spec)
		c.Assert(type_, gc.Equals, test.expectType)
		c.Assert(addr, gc.Equals, test.expectAddr)
	}
}

func (s *migrateSuite) TestStoreSource(c *gc.C) {
	st := memstore.NewStore()
	ctx := context.Background()
	err := st.UpdateIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "1"),
		Username:   "test1",
	}, store.Update{
		store.Username: store.Set,
	})
	c.Assert(err, gc.Equals, nil)
	err = st.UpdateIdentity(ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "2"),
		Username:   "test2",
	}, store.Update{
		store.Username: store.Set,
	})
	c.Assert(err, gc.Equals, nil)
	source := internal.NewStoreSource(ctx, st)
	usernames := make(map[string]struct{})
	for source.Next() {
		usernames[source.Identity().Username] = struct{}{}
	}
	c.Assert(source.Err(), gc.Equals, nil)
	c.Assert(usernames, jc.DeepEquals, map[string]struct{}{
		"test1": {},
		"test2": {},
	})
}

func (s *migrateSuite) TestStoreSourceEmpty(c *gc.C) {
	store := memstore.NewStore()
	source := internal.NewStoreSource(context.Background(), store)
	c.Assert(source.Next(), gc.Equals, false)
	c.Assert(source.Err(), gc.Equals, nil)
}

func (s *migrateSuite) TestStoreSourceError(c *gc.C) {
	testError := errgo.New("test error")
	source := internal.NewStoreSource(context.Background(), errorStore{testError})
	c.Assert(source.Next(), gc.Equals, false)
	c.Assert(source.Err(), gc.Equals, testError)
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

func (s *migrateSuite) TestCopy(c *gc.C) {
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
	c.Assert(err, gc.Equals, nil)

	identity2 := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "2"),
		Username:   "test2",
	}
	err = store1.UpdateIdentity(ctx, &identity2, store.Update{
		store.Username: store.Set,
	})
	c.Assert(err, gc.Equals, nil)

	store2 := memstore.NewStore()
	err = internal.Copy(ctx, store2, internal.NewStoreSource(ctx, store1))
	c.Assert(err, gc.Equals, nil)

	copiedIdentity1 := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "1"),
	}
	err = store2.Identity(ctx, &copiedIdentity1)
	c.Assert(err, gc.Equals, nil)
	normalize(&identity1)
	normalize(&copiedIdentity1)
	c.Assert(copiedIdentity1, jc.DeepEquals, identity1)

	copiedIdentity2 := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "2"),
	}
	err = store2.Identity(ctx, &copiedIdentity2)
	c.Assert(err, gc.Equals, nil)
	normalize(&identity2)
	normalize(&copiedIdentity2)
	c.Assert(copiedIdentity2, jc.DeepEquals, identity2)
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

func (s *migrateSuite) TestCopySrcError(c *gc.C) {
	store1 := errorStore{errgo.New("test error")}
	ctx := context.Background()

	store2 := memstore.NewStore()
	err := internal.Copy(ctx, store2, internal.NewStoreSource(ctx, store1))
	c.Assert(err, gc.ErrorMatches, "cannot read identities: test error")
}

func (s *migrateSuite) TestCopyDstError(c *gc.C) {
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
	c.Assert(err, gc.Equals, nil)

	store2 := errorStore{errgo.New("test error")}
	err = internal.Copy(ctx, store2, internal.NewStoreSource(ctx, store1))
	c.Assert(err, gc.ErrorMatches, "some updates failed")
}
