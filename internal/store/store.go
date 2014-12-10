// Copyright 2014 Canonical Ltd.

package store

import (
	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

var logger = loggo.GetLogger("identity.internal.store")

// Store represents the underlying identity data stores.
type Store struct {
	DB StoreDatabase
}

// New returns a Store that uses the given database.
func New(db *mgo.Database) (*Store, error) {
	s := &Store{
		DB: StoreDatabase{db},
	}
	if err := s.ensureIndexes(); err != nil {
		return nil, errgo.Notef(err, "cannot ensure indexes")
	}
	return s, nil
}

func (s *Store) ensureIndexes() error {
	indexes := []struct {
		c *mgo.Collection
		i mgo.Index
	}{{
		s.DB.Identities(),
		mgo.Index{
			Key:    []string{"username"},
			Unique: true,
		},
	}}
	for _, idx := range indexes {
		err := idx.c.EnsureIndex(idx.i)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

// AddIdentity adds an identity to the identities collection.
func (s *Store) AddIdentity(username string) error {
	doc := &mongodoc.Identity{
		UUID:     bson.NewObjectId().Hex(),
		UserName: username,
	}
	err := s.DB.Identities().Insert(doc)
	if mgo.IsDup(err) {
		return params.ErrAlreadyExists
	}
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// StoreDatabase wraps an mgo.DB ands adds a few convenience methods.
type StoreDatabase struct {
	*mgo.Database
}

// Copy copies the StoreDatabase and its underlying mgo session.
func (s StoreDatabase) Copy() StoreDatabase {
	return StoreDatabase{
		&mgo.Database{
			Name:    s.Name,
			Session: s.Session.Copy(),
		},
	}
}

// Close closes the store database's underlying session.
func (s StoreDatabase) Close() {
	s.Session.Close()
}

// Entities returns the mongo collection where entities are stored.
func (s StoreDatabase) Identities() *mgo.Collection {
	return s.C("identities")
}

// allCollections holds for each collection used by the identity service a
// function returning that collection.
var allCollections = []func(StoreDatabase) *mgo.Collection{
	StoreDatabase.Identities,
}

// Collections returns a slice of all the collections used
// by the identity service.
func (s StoreDatabase) Collections() []*mgo.Collection {
	cs := make([]*mgo.Collection, len(allCollections))
	for i, f := range allCollections {
		cs[i] = f(s)
	}
	return cs
}
