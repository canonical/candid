// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package candidtest

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/memsimplekv"
	"github.com/juju/testing"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/candid/meeting"
	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/memstore"
)

// A StoreSuite is a test suite that initializes a store.Store,
// meeting.MeetingStore and bakery.RootKeyStore for use with tests.
type StoreSuite struct {
	testing.IsolationSuite

	// The following stores will be initialised after calling SetUpTest

	Store              store.Store
	ProviderDataStore  store.ProviderDataStore
	MeetingStore       meeting.Store
	BakeryRootKeyStore bakery.RootKeyStore
	ACLStore           aclstore.ACLStore
}

func (s *StoreSuite) SetUpSuite(c *gc.C) {
	s.IsolationSuite.SetUpSuite(c)
}

func (s *StoreSuite) TearDownSuite(c *gc.C) {
	s.IsolationSuite.TearDownSuite(c)
}

func (s *StoreSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	s.Store = memstore.NewStore()
	s.ProviderDataStore = memstore.NewProviderDataStore()
	s.MeetingStore = memstore.NewMeetingStore()
	s.BakeryRootKeyStore = bakery.NewMemRootKeyStore()
	s.ACLStore = aclstore.NewACLStore(memsimplekv.NewStore())
}

func (s *StoreSuite) TearDownTest(c *gc.C) {
	s.IsolationSuite.TearDownTest(c)
}

// A StoreServerSuite combines a StoreSuite and a ServerSuite to provider
// an initialized server with storage.
type StoreServerSuite struct {
	StoreSuite
	ServerSuite
}

func (s *StoreServerSuite) SetUpTest(c *gc.C) {
	s.StoreSuite.SetUpTest(c)
	s.Params.Store = s.Store
	s.Params.ProviderDataStore = s.ProviderDataStore
	s.Params.MeetingStore = s.MeetingStore
	s.Params.RootKeyStore = s.BakeryRootKeyStore
	s.ServerSuite.SetUpTest(c)
}

func (s *StoreServerSuite) TearDownTest(c *gc.C) {
	s.ServerSuite.TearDownTest(c)
	s.StoreSuite.TearDownTest(c)
}

// AssertEqualIdentity asserts that the two provided identites are
// semantically equivilent.
func AssertEqualIdentity(c *gc.C, obtained, expected *store.Identity) {
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
