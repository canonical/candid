// Copyright 2014 Canonical Ltd.

package store_test

import (
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/internal/idtesting"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/params"
)

type storeSuite struct {
	idtesting.IsolatedMgoSuite
}

var _ = gc.Suite(&storeSuite{})

func (s *storeSuite) TestNew(c *gc.C) {
	db := s.Session.DB("testing")

	// Add an identity to the identities collection using mgo directly.
	err := db.C("identities").Insert(mongodoc.Identity{
		UserName: "who",
	})
	c.Assert(err, gc.IsNil)

	// Set up a new store.
	store, err := store.New(db)
	c.Assert(err, gc.IsNil)

	// Retrieve the identity using the store object.
	var doc mongodoc.Identity
	err = store.DB.Identities().Find(nil).One(&doc)
	c.Assert(err, gc.IsNil)
	c.Assert(doc.UserName, gc.Equals, "who")
}

func (s *storeSuite) TestAddIdentity(c *gc.C) {
	store, err := store.New(s.Session.DB("testing"))
	c.Assert(err, gc.IsNil)

	// Add an identity to the store.
	err = store.AddIdentity("jean-luc")
	c.Assert(err, gc.IsNil)

	// Retrieve the newly created identity.
	var doc mongodoc.Identity
	err = store.DB.Identities().Find(nil).One(&doc)
	c.Assert(err, gc.IsNil)
	c.Assert(doc.UserName, gc.Equals, "jean-luc")

	// Inserting the identity again fails because the user name must be unique.
	err = store.AddIdentity("jean-luc")
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrAlreadyExists)
}

func (s *storeSuite) TestCollections(c *gc.C) {
	store, err := store.New(s.Session.DB("testing"))
	c.Assert(err, gc.IsNil)
	colls := store.DB.Collections()
	names, err := store.DB.CollectionNames()
	c.Assert(err, gc.IsNil)

	// Some collections don't have indexes so they are created only when used.
	createdOnUse := map[string]bool{}

	// Check that all collections mentioned are actually created.
	for _, coll := range colls {
		found := false
		for _, name := range names {
			if name == coll.Name || createdOnUse[coll.Name] {
				found = true
			}
		}
		if !found {
			c.Errorf("collection %q not created", coll.Name)
		}
	}

	// Check that all created collections are mentioned in Collections.
	for _, name := range names {
		if name == "system.indexes" || name == "managedStoredResources" {
			continue
		}
		found := false
		for _, coll := range colls {
			if coll.Name == name {
				found = true
			}
		}
		if !found {
			c.Errorf("extra collection %q found", name)
		}
	}
}
