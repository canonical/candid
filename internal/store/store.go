// Copyright 2014 Canonical Ltd.

package store

import (
	"code.google.com/p/go-uuid/uuid"
	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v0/bakery"
	"gopkg.in/macaroon-bakery.v0/bakery/mgostorage"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/meeting"
	"github.com/CanonicalLtd/blues-identity/params"
)

var logger = loggo.GetLogger("identity.internal.store")
var IdentityNamespace = uuid.Parse("685c2eaa-9721-11e4-b717-a7bf1a250a86")

// Store represents the underlying identity data stores.
type Store struct {
	// DB holds the mongodb-backed identity store.
	DB StoreDatabase

	// Macaroons holds the mongodb-backed macaroon store.
	Macaroons bakery.Storage

	// Place holds the place where openid-callback rendezvous
	// are created.
	Place *meeting.Place
}

// New returns a Store that uses the given database.
func New(db *mgo.Database) (*Store, error) {
	s := &Store{
		DB:    StoreDatabase{db},
		Place: meeting.New(),
	}
	if err := s.ensureIndexes(); err != nil {
		return nil, errgo.Notef(err, "cannot ensure indexes")
	}
	ms, err := mgostorage.New(s.DB.Macaroons())
	if err != nil {
		return nil, errgo.Notef(err, "cannot create macaroon store")
	}
	s.Macaroons = ms
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
	}, {
		s.DB.Identities(),
		mgo.Index{
			Key:    []string{"external_id"},
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

// UpsertIdentity adds or updates an identity to the identities collection.
// UpsertIdentity will only update an existing entry when both the UserName and
// ExternalID match the destination record. If the Identity clashes with an existing
// Identity then an error is returned with the cause params.ErrAlreadyExists.
func (s *Store) UpsertIdentity(doc *mongodoc.Identity) error {
	doc.UUID = uuid.NewSHA1(IdentityNamespace, []byte(doc.Username)).String()
	_, err := s.DB.Identities().Upsert(
		bson.M{
			"username":    doc.Username,
			"external_id": doc.ExternalID,
		},
		doc,
	)
	if mgo.IsDup(err) {
		return errgo.WithCausef(nil, params.ErrAlreadyExists, "cannot add user: duplicate username or external_id")
	}
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// GetIdentity retrieves the identity with the given username. If the
// identity does not exist an error is returned with a cause of
// params.ErrNotFound.
func (s *Store) GetIdentity(username params.Username) (*mongodoc.Identity, error) {
	var id mongodoc.Identity
	if err := s.DB.Identities().Find(bson.M{"username": username}).One(&id); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return nil, errgo.WithCausef(err, params.ErrNotFound, "user %q not found", username)
		}
		return nil, errgo.Mask(err)
	}
	return &id, nil
}

// UpdateIdentity updates the identity with the given username. If the
// identity does not exist an error is returned with a cause of
// params.ErrNotFound.
func (s *Store) UpdateIdentity(username params.Username, update bson.D) error {
	if err := s.DB.Identities().Update(bson.D{{"username", username}}, update); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return errgo.WithCausef(err, params.ErrNotFound, "user %q not found", username)
		}
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

// Macaroons returns the mongo collection where macaroons are stored.
func (s StoreDatabase) Macaroons() *mgo.Collection {
	return s.C("macaroons")
}

// allCollections holds for each collection used by the identity service a
// function returning that collection.
var allCollections = []func(StoreDatabase) *mgo.Collection{
	StoreDatabase.Identities,
	StoreDatabase.Macaroons,
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
