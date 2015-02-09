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
	err := db.C("identities").Insert(&mongodoc.Identity{
		Username:   "who",
		ExternalID: "http://example.com/who",
		Email:      "who@example.com",
		FullName:   "Who Am I",
		Groups: []string{
			"group1",
		},
	})
	c.Assert(err, gc.IsNil)

	// Set up a new store.
	store, err := store.New(db)
	c.Assert(err, gc.IsNil)

	// Retrieve the identity using the store object.
	var doc mongodoc.Identity
	err = store.DB.Identities().Find(nil).One(&doc)
	c.Assert(err, gc.IsNil)
	c.Assert(doc.Username, gc.Equals, "who")
	c.Assert(doc.ExternalID, gc.Equals, "http://example.com/who")
	c.Assert(doc.Email, gc.Equals, "who@example.com")
	c.Assert(doc.FullName, gc.Equals, "Who Am I")
	c.Assert(doc.Groups, gc.DeepEquals, []string{"group1"})
}

func (s *storeSuite) TestUpsertIdentity(c *gc.C) {
	store, err := store.New(s.Session.DB("testing"))
	c.Assert(err, gc.IsNil)

	// Add an identity to the store.
	err = store.UpsertIdentity(&mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
		},
	})
	c.Assert(err, gc.IsNil)

	// Check the newly created identity.
	var doc mongodoc.Identity
	err = store.DB.Identities().Find(nil).One(&doc)
	c.Assert(err, gc.IsNil)
	c.Assert(doc.Username, gc.Equals, "test")
	c.Assert(doc.ExternalID, gc.Equals, "http://example.com/test")
	c.Assert(doc.Email, gc.Equals, "test@example.com")
	c.Assert(doc.FullName, gc.Equals, "Test User")
	c.Assert(doc.Groups, gc.DeepEquals, []string{"test"})

	// Update the Identity
	err = store.UpsertIdentity(&mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test2@example.com",
		FullName:   "Test User Updated",
		Groups: []string{
			"test",
			"test2",
		},
	})
	c.Assert(err, gc.IsNil)

	// Check the updated identity.
	err = store.DB.Identities().Find(nil).One(&doc)
	c.Assert(err, gc.IsNil)
	c.Assert(doc.Username, gc.Equals, "test")
	c.Assert(doc.ExternalID, gc.Equals, "http://example.com/test")
	c.Assert(doc.Email, gc.Equals, "test2@example.com")
	c.Assert(doc.FullName, gc.Equals, "Test User Updated")
	c.Assert(doc.Groups, gc.DeepEquals, []string{"test", "test2"})

	// Attempt to insert a clashing username
	err = store.UpsertIdentity(&mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test3",
		Email:      "test3@example.com",
		FullName:   "Test User III",
		Groups: []string{
			"test3",
		},
	})
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrAlreadyExists)

	// Attempt to insert a clashing external_id
	err = store.UpsertIdentity(&mongodoc.Identity{
		Username:   "test2",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
		},
	})
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrAlreadyExists)
}

func (s *storeSuite) TestCollections(c *gc.C) {
	store, err := store.New(s.Session.DB("testing"))
	c.Assert(err, gc.IsNil)
	colls := store.DB.Collections()
	names, err := store.DB.CollectionNames()
	c.Assert(err, gc.IsNil)

	// Some collections don't have indexes so they are created only when used.
	createdOnUse := map[string]bool{
		"identity_providers": true,
	}

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
