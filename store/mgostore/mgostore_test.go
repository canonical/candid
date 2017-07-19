// Copyright 2017 Canonical Ltd.

package mgostore_test

import (
	"time"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/store"
	"github.com/CanonicalLtd/blues-identity/store/mgostore"
)

var pk1 = bakery.MustGenerateKey().Public

type mgostoreSuite struct {
	testing.IsolatedMgoSuite
	store store.Store
}

var _ = gc.Suite(&mgostoreSuite{})

func (s *mgostoreSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.store, err = mgostore.NewStore(s.Session.DB("identity-test"))
	c.Assert(err, gc.Equals, nil)
}

func (s *mgostoreSuite) TestInsertIdentity(c *gc.C) {
	ctx := mgostore.ContextWithSession(context.Background(), s.Session)

	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-user"),
		Username:   "test-user",
	}
	err := s.store.UpdateIdentity(ctx, &identity, store.Update{
		store.Username: store.Set,
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity.ID, gc.Not(gc.Equals), "")

	identity2 := store.Identity{
		ID: identity.ID,
	}
	err = s.store.Identity(ctx, &identity2)
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity2, jc.DeepEquals, identity)
}

func (s *mgostoreSuite) TestUpdateIdentity(c *gc.C) {
	ctx := mgostore.ContextWithSession(context.Background(), s.Session)

	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-user"),
		Username:   "test-user",
		Name:       "Test User",
		ProviderInfo: map[string][]string{
			"f1": {"v1", "v2"},
			"f2": {"v3"},
		},
		PublicKeys: []bakery.PublicKey{pk1},
		LastLogin:  bson.Now(),
	}
	err := s.store.UpdateIdentity(ctx, &identity, store.Update{
		store.Username:     store.Set,
		store.Name:         store.Set,
		store.PublicKeys:   store.Set,
		store.ProviderInfo: store.Set,
		store.LastLogin:    store.Set,
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity.ID, gc.Not(gc.Equals), "")

	identity.Groups = []string{"g1", "g2"}
	identity.ProviderInfo = map[string][]string{
		"f1": {"v1"},
	}
	identity.ExtraInfo = map[string][]string{
		"ef1": {"v1"},
	}
	identity.LastDischarge = bson.Now()
	err = s.store.UpdateIdentity(ctx, &identity, store.Update{
		store.Name:          store.Clear,
		store.Groups:        store.Push,
		store.PublicKeys:    store.Pull,
		store.LastDischarge: store.Set,
		store.ProviderInfo:  store.Pull,
		store.ExtraInfo:     store.Push,
	})
	c.Assert(err, gc.Equals, nil)

	identity2 := store.Identity{
		ID: identity.ID,
	}
	err = s.store.Identity(ctx, &identity2)
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity2, jc.DeepEquals, store.Identity{
		ID:            identity.ID,
		ProviderID:    identity.ProviderID,
		Username:      identity.Username,
		Groups:        identity.Groups,
		LastLogin:     identity.LastLogin,
		LastDischarge: identity.LastDischarge,
		ProviderInfo: map[string][]string{
			"f1": {"v2"},
			"f2": {"v3"},
		},
		ExtraInfo: map[string][]string{
			"ef1": {"v1"},
		},
	})
}

func (s *mgostoreSuite) TestUpdateDuplicateUser(c *gc.C) {
	ctx := mgostore.ContextWithSession(context.Background(), s.Session)

	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-user-1"),
		Username:   "test-user",
	}
	err := s.store.UpdateIdentity(ctx, &identity, store.Update{
		store.Username: store.Set,
	})
	c.Assert(err, gc.Equals, nil)

	identity2 := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-user-2"),
		Username:   "test-user-2",
	}
	err = s.store.UpdateIdentity(ctx, &identity2, store.Update{
		store.Username: store.Set,
	})
	c.Assert(err, gc.Equals, nil)

	identity2.Username = "test-user"
	err = s.store.UpdateIdentity(ctx, &identity2, store.Update{
		store.Username: store.Set,
	})
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrDuplicateUsername)
	c.Assert(err, gc.ErrorMatches, `username test-user already in use`)
}

func (s *mgostoreSuite) TestUpsertDuplicateUser(c *gc.C) {
	ctx := mgostore.ContextWithSession(context.Background(), s.Session)

	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-user-1"),
		Username:   "test-user",
	}
	err := s.store.UpdateIdentity(ctx, &identity, store.Update{
		store.Username: store.Set,
	})
	c.Assert(err, gc.Equals, nil)

	identity2 := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-user-2"),
		Username:   "test-user",
	}
	err = s.store.UpdateIdentity(ctx, &identity2, store.Update{
		store.Username: store.Set,
	})
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrDuplicateUsername)
	c.Assert(err, gc.ErrorMatches, `username test-user already in use`)
}

func (s *mgostoreSuite) TestUpdateNotFound(c *gc.C) {
	ctx := mgostore.ContextWithSession(context.Background(), s.Session)

	identity := store.Identity{
		Username: "test-user",
	}
	err := s.store.UpdateIdentity(ctx, &identity, store.Update{
		store.Username: store.Set,
	})
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, `user test-user not found`)
}

func (s *mgostoreSuite) TestUpdateNotFoundNoQuery(c *gc.C) {
	ctx := mgostore.ContextWithSession(context.Background(), s.Session)

	identity := store.Identity{
		Name: "Test User",
	}
	err := s.store.UpdateIdentity(ctx, &identity, store.Update{
		store.Name: store.Set,
	})
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, `identity not specified`)
}

func (s *mgostoreSuite) TestIdentity(c *gc.C) {
	ctx := mgostore.ContextWithSession(context.Background(), s.Session)

	identity := store.Identity{
		ProviderID:    store.MakeProviderIdentity("test", "test-user"),
		Username:      "test-user",
		Name:          "Test User",
		Email:         "test@example.com",
		Groups:        []string{"g1", "g2"},
		PublicKeys:    []bakery.PublicKey{pk1},
		LastLogin:     bson.Now(),
		LastDischarge: bson.Now(),
		ProviderInfo: map[string][]string{
			"pf1": {"pf1v1", "pf1v2"},
		},
		ExtraInfo: map[string][]string{
			"ef1": {"ef1v1", "ef1v2"},
		},
	}
	err := s.store.UpdateIdentity(ctx, &identity, store.Update{
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
		ID: identity.ID,
	}
	err = s.store.Identity(ctx, &identity2)
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity2, jc.DeepEquals, identity)

	identity3 := store.Identity{
		ProviderID: identity.ProviderID,
	}
	err = s.store.Identity(ctx, &identity3)
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity3, jc.DeepEquals, identity)

	identity4 := store.Identity{
		Username: identity.Username,
	}
	err = s.store.Identity(ctx, &identity4)
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity4, jc.DeepEquals, identity)
}

func (s *mgostoreSuite) TestIdentityNotFound(c *gc.C) {
	ctx := mgostore.ContextWithSession(context.Background(), s.Session)

	identity := store.Identity{
		Username: "no-such-user",
	}
	err := s.store.Identity(ctx, &identity)
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, `user no-such-user not found`)
}

func (s *mgostoreSuite) TestIdentityNotFoundNoQuery(c *gc.C) {
	ctx := mgostore.ContextWithSession(context.Background(), s.Session)

	identity := store.Identity{}
	err := s.store.Identity(ctx, &identity)
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, `identity not specified`)
}

func (s *mgostoreSuite) TestIdentityNotFoundBadID(c *gc.C) {
	ctx := mgostore.ContextWithSession(context.Background(), s.Session)

	identity := store.Identity{
		ID: "1234",
	}
	err := s.store.Identity(ctx, &identity)
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, `identity "1234" not found`)
}

var testIdentities = []store.Identity{{
	ProviderID:    store.MakeProviderIdentity("test", "test1"),
	Username:      "test1",
	Name:          "Test User 1",
	Email:         "test1@example.com",
	Groups:        []string{"g1", "g2"},
	PublicKeys:    []bakery.PublicKey{pk1},
	LastLogin:     time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 9, 0, 0, 0, 0, time.UTC),
	ProviderInfo: map[string][]string{
		"pf1": {"pf1v1", "pf1v2"},
	},
	ExtraInfo: map[string][]string{
		"ef1": {"ef1v1", "ef1v2"},
	},
}, {
	ProviderID:    store.MakeProviderIdentity("test", "test2"),
	Username:      "test2",
	Name:          "Test User 2",
	Email:         "test2@example.com",
	LastLogin:     time.Date(2017, 1, 2, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 8, 0, 0, 0, 0, time.UTC),
}, {
	ProviderID:    store.MakeProviderIdentity("test", "test3"),
	Username:      "test3",
	Name:          "Test User 3",
	Email:         "test3@example.com",
	LastLogin:     time.Date(2017, 1, 3, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 7, 0, 0, 0, 0, time.UTC),
}, {
	ProviderID:    store.MakeProviderIdentity("test", "test4"),
	Username:      "test4",
	Name:          "Test User 4",
	Email:         "test4@example.com",
	LastLogin:     time.Date(2017, 1, 4, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 6, 0, 0, 0, 0, time.UTC),
}, {
	ProviderID:    store.MakeProviderIdentity("test", "test5"),
	Username:      "test5",
	Name:          "Test User 5",
	Email:         "test5@example.com",
	LastLogin:     time.Date(2017, 1, 5, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 5, 0, 0, 0, 0, time.UTC),
}, {
	ProviderID:    store.MakeProviderIdentity("test", "test6"),
	Username:      "test6",
	Name:          "Test User 6",
	Email:         "test6@example.com",
	LastLogin:     time.Date(2017, 1, 6, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 4, 0, 0, 0, 0, time.UTC),
}, {
	ProviderID:    store.MakeProviderIdentity("test", "test7"),
	Username:      "test7",
	Name:          "Test User 7",
	Email:         "test9@example.com",
	LastLogin:     time.Date(2017, 1, 7, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 3, 0, 0, 0, 0, time.UTC),
}, {
	ProviderID:    store.MakeProviderIdentity("test", "test8"),
	Username:      "test8",
	Name:          "Test User 8",
	Email:         "test8@example.com",
	LastLogin:     time.Date(2017, 1, 8, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 2, 0, 0, 0, 0, time.UTC),
}, {
	ProviderID:    store.MakeProviderIdentity("test", "test9"),
	Username:      "test9",
	Name:          "Test User 9",
	Email:         "test9@example.com",
	LastLogin:     time.Date(2017, 1, 9, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 1, 0, 0, 0, 0, time.UTC),
}}

var findIdentitiesTests = []struct {
	about  string
	ref    store.Identity
	filter store.Filter
	sort   []store.Sort
	skip   int
	limit  int
	expect []int
}{{
	about: "no matches",
	ref: store.Identity{
		Username: "no-such-user",
	},
	filter: store.Filter{
		store.Username: store.Equal,
	},
}, {
	about: "match username",
	ref: store.Identity{
		Username: "test1",
	},
	filter: store.Filter{
		store.Username: store.Equal,
	},
	expect: []int{0},
}, {
	about: "match name",
	ref: store.Identity{
		Name: "Test User 2",
	},
	filter: store.Filter{
		store.Name: store.Equal,
	},
	expect: []int{1},
}, {
	about: "match email",
	ref: store.Identity{
		Email: "test3@example.com",
	},
	filter: store.Filter{
		store.Email: store.Equal,
	},
	expect: []int{2},
}, {
	about: "match last login",
	ref: store.Identity{
		LastLogin: time.Date(2017, 1, 4, 0, 0, 0, 0, time.UTC),
	},
	filter: store.Filter{
		store.LastLogin: store.Equal,
	},
	expect: []int{3},
}, {
	about: "match last discharge",
	ref: store.Identity{
		LastDischarge: time.Date(2017, 2, 5, 0, 0, 0, 0, time.UTC),
	},
	filter: store.Filter{
		store.LastDischarge: store.Equal,
	},
	expect: []int{4},
}, {
	about: "match less than",
	ref: store.Identity{
		Username: "test3",
	},
	filter: store.Filter{
		store.Username: store.LessThan,
	},
	expect: []int{0, 1},
}, {
	about: "match less than or equal to",
	ref: store.Identity{
		Username: "test3",
	},
	filter: store.Filter{
		store.Username: store.LessThanOrEqual,
	},
	expect: []int{0, 1, 2},
}, {
	about: "match greater than",
	ref: store.Identity{
		Username: "test7",
	},
	filter: store.Filter{
		store.Username: store.GreaterThan,
	},
	expect: []int{7, 8},
}, {
	about: "match greater than or equal to",
	ref: store.Identity{
		Username: "test7",
	},
	filter: store.Filter{
		store.Username: store.GreaterThanOrEqual,
	},
	expect: []int{6, 7, 8},
}, {
	about: "match not equal to",
	ref: store.Identity{
		Username: "test7",
	},
	filter: store.Filter{
		store.Username: store.NotEqual,
	},
	expect: []int{0, 1, 2, 3, 4, 5, 7, 8},
}, {
	about: "sort last login - descending",
	sort: []store.Sort{{
		Field:      store.LastLogin,
		Descending: true,
	}},
	expect: []int{8, 7, 6, 5, 4, 3, 2, 1, 0},
}, {
	about: "sort last discharge - ascending",
	sort: []store.Sort{{
		Field: store.LastDischarge,
	}},
	expect: []int{8, 7, 6, 5, 4, 3, 2, 1, 0},
}, {
	about: "with skip and limit",
	sort: []store.Sort{{
		Field:      store.Username,
		Descending: true,
	}},
	skip:   2,
	limit:  3,
	expect: []int{6, 5, 4},
}}

func (s *mgostoreSuite) TestFindIdentities(c *gc.C) {
	ctx := mgostore.ContextWithSession(context.Background(), s.Session)

	for i := range testIdentities {
		var update store.Update
		if testIdentities[i].Username != "" {
			update[store.Username] = store.Set
		}
		if testIdentities[i].Name != "" {
			update[store.Name] = store.Set
		}
		if testIdentities[i].Email != "" {
			update[store.Email] = store.Set
		}
		if len(testIdentities[i].Groups) > 0 {
			update[store.Groups] = store.Set
		}
		if len(testIdentities[i].PublicKeys) > 0 {
			update[store.PublicKeys] = store.Set
		}
		if !testIdentities[i].LastLogin.IsZero() {
			update[store.LastLogin] = store.Set
		}
		if !testIdentities[i].LastDischarge.IsZero() {
			update[store.LastDischarge] = store.Set
		}
		if len(testIdentities[i].ProviderInfo) > 0 {
			update[store.ProviderInfo] = store.Set
		}
		if len(testIdentities[i].ExtraInfo) > 0 {
			update[store.ExtraInfo] = store.Set
		}
		err := s.store.UpdateIdentity(ctx, &testIdentities[i], update)
		c.Assert(err, gc.Equals, nil)
	}

	for i, test := range findIdentitiesTests {
		c.Logf("%d. %s", i, test.about)
		identities, err := s.store.FindIdentities(ctx, &test.ref, test.filter, test.sort, test.skip, test.limit)
		c.Assert(err, gc.Equals, nil)
		c.Assert(len(identities), gc.Equals, len(test.expect))
		for i, identity := range identities {
			c.Assert(identity, jc.DeepEquals, testIdentities[test.expect[i]])
		}
	}
}
