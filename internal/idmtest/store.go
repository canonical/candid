// Copyright 2017 Canonical Ltd.

package idmtest

import (
	"time"

	"github.com/juju/testing"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/mgorootkeystore"

	"github.com/CanonicalLtd/blues-identity/meeting"
	"github.com/CanonicalLtd/blues-identity/mgostore"
	"github.com/CanonicalLtd/blues-identity/store"
)

// A StoreSuite is a test suite that initializes a store.Store,
// meeting.MeetingStore and bakery.RootKeyStore for use with tests.
type StoreSuite struct {
	testing.IsolationSuite
	mgoSuite testing.MgoSuite

	// The following stores will be initialised after calling SetUpTest

	Store              store.Store
	MeetingStore       meeting.Store
	BakeryRootKeyStore bakery.RootKeyStore

	db *mgostore.Database
}

func (s *StoreSuite) SetUpSuite(c *gc.C) {
	s.IsolationSuite.SetUpSuite(c)
	s.mgoSuite.SetUpSuite(c)
}

func (s *StoreSuite) TearDownSuite(c *gc.C) {
	s.mgoSuite.TearDownSuite(c)
	s.IsolationSuite.TearDownSuite(c)
}

func (s *StoreSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	s.mgoSuite.SetUpTest(c)
	var err error
	s.db, err = mgostore.NewDatabase(s.mgoSuite.Session.DB("idmtest"))
	c.Assert(err, gc.Equals, nil)
	s.Store = s.db.Store()
	s.MeetingStore = s.db.MeetingStore()
	s.BakeryRootKeyStore = s.db.BakeryRootKeyStore(mgorootkeystore.Policy{ExpiryDuration: time.Minute})
}

func (s *StoreSuite) TearDownTest(c *gc.C) {
	s.db.Close()
	s.mgoSuite.TearDownTest(c)
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
	s.Params.MeetingStore = s.MeetingStore
	s.Params.RootKeyStore = s.BakeryRootKeyStore
	s.ServerSuite.SetUpTest(c)
}

func (s *StoreServerSuite) TearDownTest(c *gc.C) {
	s.ServerSuite.TearDownTest(c)
	s.StoreSuite.TearDownTest(c)
}
