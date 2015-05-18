// Copyright 2014 Canonical Ltd.

package store

import (
	"strings"

	"code.google.com/p/go-uuid/uuid"
	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/mgostorage"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"launchpad.net/lpad"

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

	// Launchpad holds the API base URL for launchpad.
	Launchpad lpad.APIBase
}

// New returns a Store that uses the given database.
func New(db *mgo.Database, lp lpad.APIBase) (*Store, error) {
	s := &Store{
		DB:        StoreDatabase{db},
		Place:     meeting.New(),
		Launchpad: lp,
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
	db := s.DB.Copy()
	defer db.Close()
	indexes := []struct {
		c *mgo.Collection
		i mgo.Index
	}{{
		db.Identities(),
		mgo.Index{
			Key:    []string{"username"},
			Unique: true,
		},
	}, {
		db.Identities(),
		mgo.Index{
			Key:    []string{"external_id"},
			Unique: true,
			Sparse: true,
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
	if strings.HasPrefix(doc.ExternalID, "https://login.ubuntu.com/+id/") {
		groups, err := s.getLaunchpadGroups(doc.Email)
		if err == nil {
			doc.Groups = append(doc.Groups, groups...)
		} else {
			logger.Warningf("failed to fetch list of groups from launchpad for %q: %s", doc.Email, err)
		}
	}
	db := s.DB.Copy()
	defer db.Close()
	query := bson.D{{"username", doc.Username}}
	if doc.ExternalID != "" {
		if doc.Owner != "" {
			return errgo.New("both external_id and owner specified")
		}
		query = append(query, bson.DocElem{"external_id", doc.ExternalID})
	} else if doc.Owner != "" {
		query = append(query, bson.DocElem{"owner", doc.Owner})
	} else {
		return errgo.New("no external_id or owner specified")
	}

	_, err := db.Identities().Upsert(query, doc)
	if mgo.IsDup(err) {
		return errgo.WithCausef(nil, params.ErrAlreadyExists, "cannot add user: duplicate username or external_id")
	}
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// getLaunchpadGroups tries to fetch the list of teams the user
// belongs to in launchpad. Only public teams are supported.
func (s *Store) getLaunchpadGroups(email string) ([]string, error) {
	root, err := lpad.Login(s.Launchpad, &lpad.OAuth{Consumer: "blues", Anonymous: true})
	if err != nil {
		return nil, errgo.Notef(err, "cannot connect to launchpad")
	}
	people, err := root.FindPeople(email)
	if err != nil {
		return nil, errgo.Notef(err, "cannot find user %q", email)
	}
	if people.TotalSize() != 1 {
		return nil, errgo.Newf("cannot find user %q", email)
	}
	var user *lpad.Person
	people.For(func(p *lpad.Person) error {
		user = p
		return nil
	})
	teams := user.Link("super_teams_collection_link")
	teams, err = teams.Get(nil)
	if err != nil {
		return nil, errgo.Notef(err, "cannot get team list for launchpad user %q", user.Name())
	}
	groups := make([]string, 0, teams.TotalSize())
	teams.For(func(team *lpad.Value) error {
		groups = append(groups, team.StringField("name"))
		return nil
	})
	return groups, nil
}

// GetIdentity retrieves the identity with the given username. If the
// identity does not exist an error is returned with a cause of
// params.ErrNotFound.
func (s *Store) GetIdentity(username params.Username) (*mongodoc.Identity, error) {
	db := s.DB.Copy()
	defer db.Close()
	var id mongodoc.Identity
	if err := db.Identities().Find(bson.M{"username": username}).One(&id); err != nil {
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
	db := s.DB.Copy()
	defer db.Close()
	if err := db.Identities().Update(bson.D{{"username", username}}, update); err != nil {
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
