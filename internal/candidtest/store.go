// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package candidtest

import (
	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	aclstore "github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/memsimplekv"
	"golang.org/x/net/context"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/candid/internal/identity"
	"github.com/CanonicalLtd/candid/meeting"
	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/memstore"
)

// Store implements a test fixture that contains memory-based
// store implementations for use with tests.
type Store struct {
	Store              store.Store
	ProviderDataStore  store.ProviderDataStore
	MeetingStore       meeting.Store
	BakeryRootKeyStore bakery.RootKeyStore
	ACLStore           aclstore.ACLStore
}

// NewStore returns a new Store that uses in-memory storage.
func NewStore() *Store {
	return &Store{
		Store:              memstore.NewStore(),
		ProviderDataStore:  memstore.NewProviderDataStore(),
		MeetingStore:       memstore.NewMeetingStore(),
		BakeryRootKeyStore: bakery.NewMemRootKeyStore(),
		ACLStore:           aclstore.NewACLStore(memsimplekv.NewStore()),
	}
}

// ServerParams returns parameters suitable for passing
// to NewServer that will use s as its store.
func (s *Store) ServerParams() identity.ServerParams {
	return identity.ServerParams{
		Store:             s.Store,
		ProviderDataStore: s.ProviderDataStore,
		MeetingStore:      s.MeetingStore,
		RootKeyStore:      s.BakeryRootKeyStore,
		ACLStore:          s.ACLStore,
	}
}

// AssertUser asserts that the specified user is stored in the store.
// It returns the stored identity.
func (s *Store) AssertUser(c *qt.C, id *store.Identity) *store.Identity {
	id1 := store.Identity{
		ProviderID: id.ProviderID,
		Username:   id.Username,
	}
	err := s.Store.Identity(context.Background(), &id1)
	c.Assert(err, qt.Equals, nil)
	AssertEqualIdentity(c, &id1, id)
	return &id1
}

// AssertEqualIdentity asserts that the two provided identites are
// semantically equivilent.
func AssertEqualIdentity(c *qt.C, obtained, expected *store.Identity) {
	if expected.ID == "" {
		obtained.ID = ""
	}
	normalizeInfoMap(obtained.ProviderInfo)
	normalizeInfoMap(obtained.ExtraInfo)
	normalizeInfoMap(expected.ProviderInfo)
	normalizeInfoMap(expected.ExtraInfo)
	opts := []cmp.Option{
		cmpopts.EquateEmpty(),
		cmpopts.SortSlices(func(s, t string) bool { return s < t }),
		cmpopts.SortSlices(func(x, y bakery.PublicKey) bool { return string(x.Key[:]) < string(y.Key[:]) }),
	}
	msg := cmp.Diff(obtained, expected, opts...)
	if msg != "" {
		c.Fatalf("identities do not match: %s", msg)
	}
}

// normalizeInfoMap normalizes a providerInfo or extraInfo map by
// removing any keys that have a 0 length value.
func normalizeInfoMap(m map[string][]string) {
	for k, v := range m {
		if len(v) == 0 {
			delete(m, k)
		}
	}

}
