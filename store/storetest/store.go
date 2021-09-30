// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package testing provides useful tools for testing Store
// implementations.
package storetest

import (
	"context"
	"fmt"
	"sort"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/canonical/candid/internal/auth"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/store"
)

var pk1 = bakery.MustGenerateKey().Public
var pk2 = bakery.MustGenerateKey().Public

// storeSuite contains a set of tests for Store implementations. The
// Store parameter need to be set before calling SetUpTest.
type storeSuite struct {
	newStore func(c *qt.C) store.Store

	Store store.Store
	ctx   context.Context
}

// TestStore runs a suite of tests on the given store implementation.
func TestStore(c *qt.C, newStore func(c *qt.C) store.Store) {
	qtsuite.Run(c, &storeSuite{
		newStore: newStore,
	})
}

func (s *storeSuite) Init(c *qt.C) {
	s.Store = s.newStore(c)

	ctx, close := s.Store.Context(context.Background())
	c.Defer(close)
	s.ctx = ctx
}

var updateIdentityTests = []struct {
	about            string
	startIdentity    *store.Identity
	updateIdentity   *store.Identity
	update           store.Update
	expectError      string
	expectErrorCause error
	expectIdentity   *store.Identity
}{{
	about:          "new identity",
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.Username: store.Set,
	},
	expectIdentity: &store.Identity{},
}, {
	about: "new identity with existing username",
	updateIdentity: &store.Identity{
		Username: "existing-user",
	},
	update: store.Update{
		store.Username: store.Set,
	},
	expectError:      `username existing-user already in use`,
	expectErrorCause: store.ErrDuplicateUsername,
}, {
	about:         "set username",
	startIdentity: &store.Identity{},
	updateIdentity: &store.Identity{
		Username: "bob",
	},
	update: store.Update{
		store.Username: store.Set,
	},
	expectIdentity: &store.Identity{
		Username: "bob",
	},
}, {
	about:         "set username to existing username",
	startIdentity: &store.Identity{},
	updateIdentity: &store.Identity{
		Username: "existing-user",
	},
	update: store.Update{
		store.Username: store.Set,
	},
	expectError:      `username existing-user already in use`,
	expectErrorCause: store.ErrDuplicateUsername,
	expectIdentity:   &store.Identity{},
}, {
	about: "set name",
	startIdentity: &store.Identity{
		Name: "Test User",
	},
	updateIdentity: &store.Identity{
		Name: "Test User II",
	},
	update: store.Update{
		store.Name: store.Set,
	},
	expectIdentity: &store.Identity{
		Name: "Test User II",
	},
}, {
	about: "clear name",
	startIdentity: &store.Identity{
		Name: "Test User",
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.Name: store.Clear,
	},
	expectIdentity: &store.Identity{},
}, {
	about: "set email",
	startIdentity: &store.Identity{
		Email: "test@example.com",
	},
	updateIdentity: &store.Identity{
		Email: "test2@example.com",
	},
	update: store.Update{
		store.Email: store.Set,
	},
	expectIdentity: &store.Identity{
		Email: "test2@example.com",
	},
}, {
	about: "clear email",
	startIdentity: &store.Identity{
		Email: "test@example.com",
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.Email: store.Clear,
	},
	expectIdentity: &store.Identity{},
}, {
	about: "set last discharge",
	startIdentity: &store.Identity{
		LastDischarge: time.Date(2017, 12, 25, 0, 0, 0, 0, time.UTC),
	},
	updateIdentity: &store.Identity{
		LastDischarge: time.Date(2017, 12, 26, 0, 0, 0, 0, time.UTC),
	},
	update: store.Update{
		store.LastDischarge: store.Set,
	},
	expectIdentity: &store.Identity{
		LastDischarge: time.Date(2017, 12, 26, 0, 0, 0, 0, time.UTC),
	},
}, {
	about: "clear last discharge",
	startIdentity: &store.Identity{
		LastDischarge: time.Date(2017, 12, 25, 0, 0, 0, 0, time.UTC),
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.LastDischarge: store.Clear,
	},
	expectIdentity: &store.Identity{},
}, {
	about: "set last login",
	startIdentity: &store.Identity{
		LastLogin: time.Date(2017, 12, 25, 0, 0, 0, 0, time.UTC),
	},
	updateIdentity: &store.Identity{
		LastLogin: time.Date(2017, 12, 26, 0, 0, 0, 0, time.UTC),
	},
	update: store.Update{
		store.LastLogin: store.Set,
	},
	expectIdentity: &store.Identity{
		LastLogin: time.Date(2017, 12, 26, 0, 0, 0, 0, time.UTC),
	},
}, {
	about: "clear last login",
	startIdentity: &store.Identity{
		LastLogin: time.Date(2017, 12, 25, 0, 0, 0, 0, time.UTC),
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.LastLogin: store.Clear,
	},
	expectIdentity: &store.Identity{},
}, {
	about: "set groups",
	startIdentity: &store.Identity{
		Groups: []string{"g1", "g2"},
	},
	updateIdentity: &store.Identity{
		Groups: []string{"g3", "g4"},
	},
	update: store.Update{
		store.Groups: store.Set,
	},
	expectIdentity: &store.Identity{
		Groups: []string{"g3", "g4"},
	},
}, {
	about: "set groups empty",
	startIdentity: &store.Identity{
		Groups: []string{"g1", "g2"},
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.Groups: store.Set,
	},
	expectIdentity: &store.Identity{},
}, {
	about: "clear groups",
	startIdentity: &store.Identity{
		Groups: []string{"g1", "g2"},
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.Groups: store.Clear,
	},
	expectIdentity: &store.Identity{},
}, {
	about: "push groups",
	startIdentity: &store.Identity{
		Groups: []string{"g1", "g2"},
	},
	updateIdentity: &store.Identity{
		Groups: []string{"g3", "g4"},
	},
	update: store.Update{
		store.Groups: store.Push,
	},
	expectIdentity: &store.Identity{
		Groups: []string{"g1", "g2", "g3", "g4"},
	},
}, {
	about: "push groups empty",
	startIdentity: &store.Identity{
		Groups: []string{"g1", "g2"},
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.Groups: store.Push,
	},
	expectIdentity: &store.Identity{
		Groups: []string{"g1", "g2"},
	},
}, {
	about: "pull groups",
	startIdentity: &store.Identity{
		Groups: []string{"g1", "g2", "g3", "g4"},
	},
	updateIdentity: &store.Identity{
		Groups: []string{"g2", "g4"},
	},
	update: store.Update{
		store.Groups: store.Pull,
	},
	expectIdentity: &store.Identity{
		Groups: []string{"g1", "g3"},
	},
}, {
	about: "pull groups empty",
	startIdentity: &store.Identity{
		Groups: []string{"g1", "g2", "g3", "g4"},
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.Groups: store.Pull,
	},
	expectIdentity: &store.Identity{
		Groups: []string{"g1", "g2", "g3", "g4"},
	},
}, {
	about: "set public keys",
	startIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk1},
	},
	updateIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk2},
	},
	update: store.Update{
		store.PublicKeys: store.Set,
	},
	expectIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk2},
	},
}, {
	about: "set public keys empty",
	startIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk1},
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.PublicKeys: store.Set,
	},
	expectIdentity: &store.Identity{},
}, {
	about: "clear public keys",
	startIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk1, pk2},
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.PublicKeys: store.Clear,
	},
	expectIdentity: &store.Identity{},
}, {
	about: "push public keys",
	startIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk1},
	},
	updateIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk2},
	},
	update: store.Update{
		store.PublicKeys: store.Push,
	},
	expectIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk1, pk2},
	},
}, {
	about: "push public keys empty",
	startIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk1},
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.PublicKeys: store.Push,
	},
	expectIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk1},
	},
}, {
	about: "pull public keys",
	startIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk1, pk2},
	},
	updateIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk1},
	},
	update: store.Update{
		store.PublicKeys: store.Pull,
	},
	expectIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk2},
	},
}, {
	about: "pull public keys empty",
	startIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk1, pk2},
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.PublicKeys: store.Pull,
	},
	expectIdentity: &store.Identity{
		PublicKeys: []bakery.PublicKey{pk1, pk2},
	},
}, {
	about: "set provider info",
	startIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"e", "f"},
		},
	},
	update: store.Update{
		store.ProviderInfo: store.Set,
	},
	expectIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"e", "f"},
			"k2": {"c", "d"},
		},
	},
}, {
	about: "set provider info empty",
	startIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": nil,
		},
	},
	update: store.Update{
		store.ProviderInfo: store.Set,
	},
	expectIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k2": {"c", "d"},
		},
	},
}, {
	about: "clear provider info",
	startIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k2": nil,
		},
	},
	update: store.Update{
		store.ProviderInfo: store.Clear,
	},
	expectIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b"},
		},
	},
}, {
	about: "push provider info",
	startIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"e", "f"},
		},
	},
	update: store.Update{
		store.ProviderInfo: store.Push,
	},
	expectIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b", "e", "f"},
			"k2": {"c", "d"},
		},
	},
}, {
	about: "push provider info empty",
	startIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": nil,
		},
	},
	update: store.Update{
		store.ProviderInfo: store.Push,
	},
	expectIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
}, {
	about: "pull provider info",
	startIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k2": {"c"},
		},
	},
	update: store.Update{
		store.ProviderInfo: store.Pull,
	},
	expectIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"d"},
		},
	},
}, {
	about: "pull provider info empty",
	startIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k2": nil,
		},
	},
	update: store.Update{
		store.ProviderInfo: store.Pull,
	},
	expectIdentity: &store.Identity{
		ProviderInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
}, {
	about: "set extra info",
	startIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"e", "f"},
		},
	},
	update: store.Update{
		store.ExtraInfo: store.Set,
	},
	expectIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"e", "f"},
			"k2": {"c", "d"},
		},
	},
}, {
	about: "set extra info empty",
	startIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": nil,
		},
	},
	update: store.Update{
		store.ExtraInfo: store.Set,
	},
	expectIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k2": {"c", "d"},
		},
	},
}, {
	about: "clear extra info",
	startIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k2": nil,
		},
	},
	update: store.Update{
		store.ExtraInfo: store.Clear,
	},
	expectIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b"},
		},
	},
}, {
	about: "push extra info",
	startIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"e", "f"},
		},
	},
	update: store.Update{
		store.ExtraInfo: store.Push,
	},
	expectIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b", "e", "f"},
			"k2": {"c", "d"},
		},
	},
}, {
	about: "push extra info empty",
	startIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": nil,
		},
	},
	update: store.Update{
		store.ExtraInfo: store.Push,
	},
	expectIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
}, {
	about: "pull extra info",
	startIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k2": {"c"},
		},
	},
	update: store.Update{
		store.ExtraInfo: store.Pull,
	},
	expectIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"d"},
		},
	},
}, {
	about: "pull extra info empty",
	startIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
	updateIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k2": nil,
		},
	},
	update: store.Update{
		store.ExtraInfo: store.Pull,
	},
	expectIdentity: &store.Identity{
		ExtraInfo: map[string][]string{
			"k1": {"a", "b"},
			"k2": {"c", "d"},
		},
	},
}, {
	about:         "set owner",
	startIdentity: &store.Identity{},
	updateIdentity: &store.Identity{
		Owner: auth.AdminProviderID,
	},
	update: store.Update{
		store.Owner: store.Set,
	},
	expectIdentity: &store.Identity{
		Owner: auth.AdminProviderID,
	},
}, {
	about: "clear owner",
	startIdentity: &store.Identity{
		Owner: auth.AdminProviderID,
	},
	updateIdentity: &store.Identity{},
	update: store.Update{
		store.Owner: store.Clear,
	},
	expectIdentity: &store.Identity{},
}, {
	about: "username not found",
	updateIdentity: &store.Identity{
		Name: "Test User",
	},
	update: store.Update{
		store.Name: store.Set,
	},
	expectError:      `user .* not found`,
	expectErrorCause: store.ErrNotFound,
}, {
	about: "id not found",
	updateIdentity: &store.Identity{
		ID:   "not-an-id",
		Name: "Test User",
	},
	update: store.Update{
		store.Name: store.Set,
	},
	expectError:      `identity "not-an-id" not found`,
	expectErrorCause: store.ErrNotFound,
}, {
	about: "providerid not found",
	updateIdentity: &store.Identity{
		ProviderID: "not-a-providerid",
		Name:       "Test User",
	},
	update: store.Update{
		store.Name: store.Set,
	},
	expectError:      `identity "not-a-providerid" not found`,
	expectErrorCause: store.ErrNotFound,
}, {
	about:          "empty update",
	startIdentity:  &store.Identity{},
	updateIdentity: &store.Identity{},
	update:         store.Update{},
}, {
	about: "providerID empty update",
	startIdentity: &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "empty-update-user"),
	},
	updateIdentity: &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "empty-update-user"),
	},
	update: store.Update{},
}}

func (s *storeSuite) TestUpdateIdentity(c *qt.C) {
	err := s.Store.UpdateIdentity(
		s.ctx,
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("test", "existing-user"),
			Username:   "existing-user",
		},
		store.Update{
			store.Username: store.Set,
		},
	)
	c.Assert(err, qt.IsNil)

	for i, test := range updateIdentityTests {
		c.Run(test.about, func(c *qt.C) {
			username := fmt.Sprintf("user%d", i)
			pid := store.MakeProviderIdentity("test", username)

			if test.startIdentity != nil {
				update := store.Update{
					store.Username:     store.Set,
					store.Name:         store.Set,
					store.Email:        store.Set,
					store.Groups:       store.Set,
					store.PublicKeys:   store.Set,
					store.ProviderInfo: store.Set,
					store.ExtraInfo:    store.Set,
				}
				if test.startIdentity.ProviderID == "" {
					test.startIdentity.ProviderID = pid
				}
				if test.startIdentity.Username == "" {
					test.startIdentity.Username = username
				}
				if !test.startIdentity.LastDischarge.IsZero() {
					update[store.LastDischarge] = store.Set
				}
				if !test.startIdentity.LastLogin.IsZero() {
					update[store.LastLogin] = store.Set
				}
				err := s.Store.UpdateIdentity(s.ctx, test.startIdentity, update)
				c.Assert(err, qt.IsNil)
			}

			if test.updateIdentity.Username == "" && test.updateIdentity.ProviderID == "" {
				test.updateIdentity.Username = username
			}

			if test.update[store.Username] == store.Set {
				if test.updateIdentity.ProviderID == "" {
					test.updateIdentity.ProviderID = pid
				}
			}

			err := s.Store.UpdateIdentity(s.ctx, test.updateIdentity, test.update)
			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				if test.expectErrorCause != nil {
					c.Assert(errgo.Cause(err), qt.Equals, test.expectErrorCause)
				}
			} else {
				c.Assert(err, qt.IsNil)
			}
			if test.expectIdentity == nil {
				return
			}
			if test.expectIdentity.ProviderID == "" {
				test.expectIdentity.ProviderID = pid
			}
			if test.expectIdentity.Username == "" {
				test.expectIdentity.Username = username
			}
			obtained := store.Identity{
				ProviderID: test.expectIdentity.ProviderID,
			}
			err = s.Store.Identity(s.ctx, &obtained)
			c.Assert(err, qt.IsNil)
			candidtest.AssertEqualIdentity(c, &obtained, test.expectIdentity)
		})
	}
}

func (s *storeSuite) TestUpdateNotFoundNoQuery(c *qt.C) {
	identity := store.Identity{
		Name: "Test User",
	}
	err := s.Store.UpdateIdentity(s.ctx, &identity, store.Update{
		store.Name: store.Set,
	})
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
	c.Assert(err, qt.ErrorMatches, `identity not specified`)
}

func (s *storeSuite) TestInsertDuplicateUsername(c *qt.C) {
	err := s.Store.UpdateIdentity(
		s.ctx,
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("test", "existing-user"),
			Username:   "existing-user",
		},
		store.Update{
			store.Username: store.Set,
		},
	)
	c.Assert(err, qt.IsNil)

	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-user"),
		Username:   "existing-user",
	}
	err = s.Store.UpdateIdentity(
		s.ctx,
		&identity,
		store.Update{
			store.Username: store.Set,
		},
	)
	c.Assert(err, qt.ErrorMatches, `username existing-user already in use`)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrDuplicateUsername)

	identity2 := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-user"),
	}
	err = s.Store.Identity(s.ctx, &identity2)
	c.Assert(err, qt.ErrorMatches, `identity "test:test-user" not found`)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
}

func (s *storeSuite) TestUpdateIDDuplicateUsername(c *qt.C) {
	err := s.Store.UpdateIdentity(
		s.ctx,
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("test", "existing-user"),
			Username:   "existing-user",
		},
		store.Update{
			store.Username: store.Set,
		},
	)
	c.Assert(err, qt.IsNil)

	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-user"),
		Username:   "test-user",
	}
	err = s.Store.UpdateIdentity(
		s.ctx,
		&identity,
		store.Update{
			store.Username: store.Set,
		},
	)
	c.Assert(err, qt.IsNil)

	identity2 := store.Identity{
		ID:       identity.ID,
		Username: "existing-user",
	}
	err = s.Store.UpdateIdentity(
		s.ctx,
		&identity2,
		store.Update{
			store.Username: store.Set,
		},
	)
	c.Assert(err, qt.ErrorMatches, `username existing-user already in use`)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrDuplicateUsername)
}

func (s *storeSuite) TestUpdateIDEmpty(c *qt.C) {
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "test-user"),
		Username:   "test-user",
	}
	err := s.Store.UpdateIdentity(
		s.ctx,
		&identity,
		store.Update{
			store.Username: store.Set,
		},
	)
	c.Assert(err, qt.IsNil)

	identity2 := store.Identity{
		ID: identity.ID,
	}
	err = s.Store.UpdateIdentity(
		s.ctx,
		&identity2,
		store.Update{},
	)
	c.Assert(err, qt.IsNil)
}

func (s *storeSuite) TestIdentity(c *qt.C) {
	identity := store.Identity{
		ProviderID:    store.MakeProviderIdentity("test", "test-user"),
		Username:      "test-user",
		Name:          "Test User",
		Email:         "test@example.com",
		Groups:        []string{"g1", "g2"},
		PublicKeys:    []bakery.PublicKey{pk1},
		LastLogin:     time.Date(2017, 12, 25, 0, 0, 0, 0, time.UTC),
		LastDischarge: time.Date(2017, 12, 25, 0, 0, 0, 0, time.UTC),
		ProviderInfo: map[string][]string{
			"pf1": {"pf1v1", "pf1v2"},
		},
		ExtraInfo: map[string][]string{
			"ef1": {"ef1v1", "ef1v2"},
		},
		Owner: store.MakeProviderIdentity("test", "test-admin"),
	}
	err := s.Store.UpdateIdentity(s.ctx, &identity, store.Update{
		store.Username:      store.Set,
		store.Name:          store.Set,
		store.Email:         store.Set,
		store.Groups:        store.Set,
		store.PublicKeys:    store.Set,
		store.LastLogin:     store.Set,
		store.LastDischarge: store.Set,
		store.ProviderInfo:  store.Set,
		store.ExtraInfo:     store.Set,
		store.Owner:         store.Set,
	})
	c.Assert(err, qt.IsNil)

	identity2 := store.Identity{
		ID: identity.ID,
	}
	err = s.Store.Identity(s.ctx, &identity2)
	c.Assert(err, qt.IsNil)
	c.Assert(identity2, qt.DeepEquals, identity)

	identity3 := store.Identity{
		ProviderID: identity.ProviderID,
	}
	err = s.Store.Identity(s.ctx, &identity3)
	c.Assert(err, qt.IsNil)
	c.Assert(identity3, qt.DeepEquals, identity)

	identity4 := store.Identity{
		Username: identity.Username,
	}
	err = s.Store.Identity(s.ctx, &identity4)
	c.Assert(err, qt.IsNil)
	c.Assert(identity4, qt.DeepEquals, identity)
}

func (s *storeSuite) TestIdentityNotFound(c *qt.C) {
	identity := store.Identity{
		Username: "no-such-user",
	}
	err := s.Store.Identity(s.ctx, &identity)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
	c.Assert(err, qt.ErrorMatches, `user no-such-user not found`)
}

func (s *storeSuite) TestIdentityNotFoundNoQuery(c *qt.C) {
	identity := store.Identity{}
	err := s.Store.Identity(s.ctx, &identity)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
	c.Assert(err, qt.ErrorMatches, `identity not specified`)
}

func (s *storeSuite) TestIdentityNotFoundBadID(c *qt.C) {
	identity := store.Identity{
		ID: "1234",
	}
	err := s.Store.Identity(s.ctx, &identity)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
	c.Assert(err, qt.ErrorMatches, `identity "1234" not found`)
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
	Owner:         "test:test1",
}, {
	ProviderID:    store.MakeProviderIdentity("test", "test7"),
	Username:      "test7",
	Name:          "Test User 7",
	Email:         "test9@example.com",
	LastLogin:     time.Date(2017, 1, 7, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 3, 0, 0, 0, 0, time.UTC),
	Owner:         "test:test2",
}, {
	ProviderID:    store.MakeProviderIdentity("test", "test8"),
	Username:      "test8",
	Name:          "Test User 8",
	Email:         "test8@example.com",
	LastLogin:     time.Date(2017, 1, 8, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 2, 0, 0, 0, 0, time.UTC),
	Owner:         "test:test3",
}, {
	ProviderID:    store.MakeProviderIdentity("test", "test9"),
	Username:      "test9",
	Name:          "Test User 9",
	Email:         "test9@example.com",
	LastLogin:     time.Date(2017, 1, 9, 0, 0, 0, 0, time.UTC),
	LastDischarge: time.Date(2017, 2, 1, 0, 0, 0, 0, time.UTC),
	Owner:         "test:test4",
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
	about: "provider ID equal",
	ref: store.Identity{
		ProviderID: "test:test1",
	},
	filter: store.Filter{
		store.ProviderID: store.Equal,
	},
	expect: []int{0},
}, {
	about: "provider ID not equal",
	ref: store.Identity{
		ProviderID: "test:test1",
	},
	filter: store.Filter{
		store.ProviderID: store.NotEqual,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{1, 2, 3, 4, 5, 6, 7, 8},
}, {
	about: "provider ID greater than",
	ref: store.Identity{
		ProviderID: "test:test5",
	},
	filter: store.Filter{
		store.ProviderID: store.GreaterThan,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{5, 6, 7, 8},
}, {
	about: "provider ID less than",
	ref: store.Identity{
		ProviderID: "test:test5",
	},
	filter: store.Filter{
		store.ProviderID: store.LessThan,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{0, 1, 2, 3},
}, {
	about: "provider ID greater than or equal",
	ref: store.Identity{
		ProviderID: "test:test5",
	},
	filter: store.Filter{
		store.ProviderID: store.GreaterThanOrEqual,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{4, 5, 6, 7, 8},
}, {
	about: "provider ID less than or equal",
	ref: store.Identity{
		ProviderID: "test:test5",
	},
	filter: store.Filter{
		store.ProviderID: store.LessThanOrEqual,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{0, 1, 2, 3, 4},
}, {
	about: "username equal",
	ref: store.Identity{
		Username: "test1",
	},
	filter: store.Filter{
		store.Username: store.Equal,
	},
	expect: []int{0},
}, {
	about: "username not equal",
	ref: store.Identity{
		Username: "test1",
	},
	filter: store.Filter{
		store.Username: store.NotEqual,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{1, 2, 3, 4, 5, 6, 7, 8},
}, {
	about: "username greater than",
	ref: store.Identity{
		Username: "test5",
	},
	filter: store.Filter{
		store.Username: store.GreaterThan,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{5, 6, 7, 8},
}, {
	about: "username less than",
	ref: store.Identity{
		Username: "test5",
	},
	filter: store.Filter{
		store.Username: store.LessThan,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{0, 1, 2, 3},
}, {
	about: "username greater than or equal",
	ref: store.Identity{
		Username: "test5",
	},
	filter: store.Filter{
		store.Username: store.GreaterThanOrEqual,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{4, 5, 6, 7, 8},
}, {
	about: "username less than or equal",
	ref: store.Identity{
		Username: "test5",
	},
	filter: store.Filter{
		store.Username: store.LessThanOrEqual,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{0, 1, 2, 3, 4},
}, {
	about: "name equal",
	ref: store.Identity{
		Name: "Test User 1",
	},
	filter: store.Filter{
		store.Name: store.Equal,
	},
	expect: []int{0},
}, {
	about: "name not equal",
	ref: store.Identity{
		Name: "Test User 1",
	},
	filter: store.Filter{
		store.Name: store.NotEqual,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{1, 2, 3, 4, 5, 6, 7, 8},
}, {
	about: "name greater than",
	ref: store.Identity{
		Name: "Test User 5",
	},
	filter: store.Filter{
		store.Name: store.GreaterThan,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{5, 6, 7, 8},
}, {
	about: "name less than",
	ref: store.Identity{
		Name: "Test User 5",
	},
	filter: store.Filter{
		store.Name: store.LessThan,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{0, 1, 2, 3},
}, {
	about: "name greater than or equal",
	ref: store.Identity{
		Name: "Test User 5",
	},
	filter: store.Filter{
		store.Name: store.GreaterThanOrEqual,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{4, 5, 6, 7, 8},
}, {
	about: "name less than or equal",
	ref: store.Identity{
		Name: "Test User 5",
	},
	filter: store.Filter{
		store.Name: store.LessThanOrEqual,
	},
	sort:   []store.Sort{{Field: store.Username}},
	expect: []int{0, 1, 2, 3, 4},
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
}, {
	about: "match owner",
	ref: store.Identity{
		Owner: "test:test1",
	},
	filter: store.Filter{
		store.Owner: store.Equal,
	},
	expect: []int{5},
}}

func (s *storeSuite) TestFindIdentities(c *qt.C) {
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
		if testIdentities[i].Owner != "" {
			update[store.Owner] = store.Set
		}
		err := s.Store.UpdateIdentity(s.ctx, &testIdentities[i], update)
		c.Assert(err, qt.IsNil)
	}

	for i, test := range findIdentitiesTests {
		c.Logf("%d. %s", i, test.about)
		identities, err := s.Store.FindIdentities(s.ctx, &test.ref, test.filter, test.sort, test.skip, test.limit)
		c.Assert(err, qt.IsNil)
		c.Assert(len(identities), qt.Equals, len(test.expect))
		for i, identity := range identities {
			candidtest.AssertEqualIdentity(c, &identity, &testIdentities[test.expect[i]])
		}
	}
}

func (s *storeSuite) TestIdentityCounts(c *qt.C) {
	idps := []string{"a", "b", "c", "a", "b", "a"}
	for i, idp := range idps {
		username := fmt.Sprintf("user%d", i)
		err := s.Store.UpdateIdentity(s.ctx, &store.Identity{
			ProviderID: store.MakeProviderIdentity(idp, username),
			Username:   username,
		}, store.Update{
			store.Username: store.Set,
		})
		c.Assert(err, qt.IsNil)
	}
	counts, err := s.Store.IdentityCounts(s.ctx)
	c.Assert(err, qt.IsNil)
	c.Assert(counts, qt.DeepEquals, map[string]int{
		"a": 3,
		"b": 2,
		"c": 1,
	})
}

func (s *storeSuite) TestUserCredentials(c *qt.C) {
	// add an identity
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "existing-user"),
		Username:   "test-user",
	}
	err := s.Store.UpdateIdentity(
		s.ctx,
		&identity,
		store.Update{
			store.Username: store.Set,
		},
	)
	c.Assert(err, qt.IsNil)

	err = s.Store.ClearMFACredentials(s.ctx, string(identity.ProviderID))
	c.Assert(err, qt.Equals, nil)

	// no credentials exist for the created user
	creds, err := s.Store.UserMFACredentials(s.ctx, identity.ID)
	c.Assert(err, qt.IsNil)
	c.Assert(creds, qt.DeepEquals, []store.MFACredential(nil))

	// add a credential for the created user
	cred := store.MFACredential{
		ID:                     []byte("test id 1"),
		ProviderID:             identity.ProviderID,
		Name:                   "test credential 1",
		PublicKey:              []byte("public key 1"),
		AttestationType:        "test attestation type",
		AuthenticatorGUID:      []byte("guid 1"),
		AuthenticatorSignCount: 1,
	}
	err = s.Store.AddMFACredential(s.ctx, cred)
	c.Assert(err, qt.IsNil)

	// try fetching credentials for the test user
	creds, err = s.Store.UserMFACredentials(s.ctx, string(identity.ProviderID))
	c.Assert(err, qt.IsNil)
	c.Assert(creds, qt.DeepEquals, []store.MFACredential{cred})

	// try adding a credential with a duplicate name
	cred1 := cred
	cred1.ID = []byte("test id 2")
	err = s.Store.AddMFACredential(s.ctx, cred1)
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrDuplicateCredential)

	cred2 := store.MFACredential{
		ID:                     []byte("test id 3"),
		ProviderID:             identity.ProviderID,
		Name:                   "test credential 2",
		PublicKey:              []byte("public key 2"),
		AttestationType:        "test attestation type",
		AuthenticatorGUID:      []byte("guid 2"),
		AuthenticatorSignCount: 2,
	}
	err = s.Store.AddMFACredential(s.ctx, cred2)
	c.Assert(err, qt.IsNil)

	// try fetching credentials for the test user
	creds, err = s.Store.UserMFACredentials(s.ctx, string(identity.ProviderID))
	c.Assert(err, qt.IsNil)
	sort.Slice(creds, func(i, j int) bool {
		return creds[i].Name < creds[j].Name
	})
	c.Assert(creds, qt.DeepEquals, []store.MFACredential{cred, cred2})

	err = s.Store.IncrementMFACredentialSignCount(s.ctx, cred.ID)
	c.Assert(err, qt.IsNil)
	err = s.Store.IncrementMFACredentialSignCount(s.ctx, cred2.ID)
	c.Assert(err, qt.IsNil)
	err = s.Store.IncrementMFACredentialSignCount(s.ctx, cred2.ID)
	c.Assert(err, qt.IsNil)

	// fetch the user credentials and verify sign counts match
	// expected values
	cred.AuthenticatorSignCount = 2
	cred2.AuthenticatorSignCount = 4
	creds, err = s.Store.UserMFACredentials(s.ctx, string(identity.ProviderID))
	c.Assert(err, qt.IsNil)
	sort.Slice(creds, func(i, j int) bool {
		return creds[i].Name < creds[j].Name
	})
	c.Assert(creds, qt.DeepEquals, []store.MFACredential{cred, cred2})

	err = s.Store.ClearMFACredentials(s.ctx, string(identity.ProviderID))
	c.Assert(err, qt.Equals, nil)
	creds, err = s.Store.UserMFACredentials(s.ctx, string(identity.ProviderID))
	c.Assert(err, qt.IsNil)
	c.Assert(creds, qt.HasLen, 0)
}
