// Copyright 2017 Canonical Ltd.

package mgostore

import (
	"fmt"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/store"
)

const identitiesCollection = "identities"

// identityStore is a store.Store implementation that uses a mongodb database to
// store the data.
type identityStore struct {
	db *Database
}

func (s *identityStore) Context(ctx context.Context) (_ context.Context, cancel func()) {
	return s.db.context(ctx)
}

// Identity implements store.Store.Identity by retrieving the specified
// identity from the mongodb database. The given context must have a
// mgo.Session added using ContextWithSession.
func (s *identityStore) Identity(ctx context.Context, identity *store.Identity) error {
	coll := s.db.c(ctx, identitiesCollection)
	defer coll.Database.Session.Close()

	var doc identityDocument
	if err := coll.Find(identityQuery(identity)).One(&doc); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return store.NotFoundError(identity.ID, identity.ProviderID, identity.Username)
		}
		return errgo.Mask(err)
	}
	identity.ID = doc.ID.Hex()
	identity.ProviderID = store.ProviderIdentity(doc.ProviderID)
	identity.Username = doc.Username
	identity.Name = doc.Name
	identity.Email = doc.Email
	identity.Groups = doc.Groups
	identity.PublicKeys = doc.PublicKeys()
	identity.LastLogin = doc.LastLogin
	identity.LastDischarge = doc.LastDischarge
	identity.ProviderInfo = doc.ProviderInfo
	identity.ExtraInfo = doc.ExtraInfo
	return nil
}

func identityQuery(identity *store.Identity) bson.D {
	switch {
	case identity.ID != "":
		if !bson.IsObjectIdHex(identity.ID) {
			break
		}
		return bson.D{{"_id", bson.ObjectIdHex(identity.ID)}}
	case identity.ProviderID != "":
		return bson.D{{"providerid", identity.ProviderID}}
	case identity.Username != "":
		return bson.D{{"username", identity.Username}}
	default:
	}
	// The identity specifies no identifying fields, return something
	// that will fail.
	return bson.D{{"_id", ""}}
}

// FindIdentities implements store.Store.FindIdentities by querying the
// mongodb database. The given context must have a mgo.Session added
// using ContextWithSession.
func (s *identityStore) FindIdentities(ctx context.Context, ref *store.Identity, filter store.Filter, sort []store.Sort, skip, limit int) ([]store.Identity, error) {
	coll := s.db.c(ctx, identitiesCollection)
	defer coll.Database.Session.Close()

	q := coll.Find(makeQuery(ref, filter))
	if len(sort) > 0 {
		ssort := make([]string, len(sort))
		for i, s := range sort {
			if s.Descending {
				ssort[i] = fmt.Sprintf("-%s", fieldNames[s.Field])
			} else {
				ssort[i] = fieldNames[s.Field]
			}
		}
		q = q.Sort(ssort...)
	}
	if skip > 0 {
		q = q.Skip(skip)
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	it := q.Iter()
	identities := make([]store.Identity, 0, limit)
	var doc identityDocument
	for it.Next(&doc) {
		identities = append(identities, store.Identity{
			ID:            doc.ID.Hex(),
			ProviderID:    store.ProviderIdentity(doc.ProviderID),
			Username:      doc.Username,
			Email:         doc.Email,
			Name:          doc.Name,
			Groups:        doc.Groups,
			PublicKeys:    doc.PublicKeys(),
			LastLogin:     doc.LastLogin,
			LastDischarge: doc.LastDischarge,
			ProviderInfo:  doc.ProviderInfo,
			ExtraInfo:     doc.ExtraInfo,
		})
	}
	if err := it.Err(); err != nil {
		return nil, errgo.Mask(err)
	}
	return identities, nil
}

func makeQuery(ref *store.Identity, filter store.Filter) bson.D {
	query := make(bson.D, 0, store.NumFields)
	query = appendComparison(query, fieldNames[store.ProviderID], filter[store.ProviderID], ref.ProviderID)
	query = appendComparison(query, fieldNames[store.Username], filter[store.Username], ref.Username)
	query = appendComparison(query, fieldNames[store.Name], filter[store.Name], ref.Name)
	query = appendComparison(query, fieldNames[store.Email], filter[store.Email], ref.Email)
	query = appendComparison(query, fieldNames[store.LastLogin], filter[store.LastLogin], ref.LastLogin)
	query = appendComparison(query, fieldNames[store.LastDischarge], filter[store.LastDischarge], ref.LastDischarge)
	return query
}

func appendComparison(query bson.D, fieldName string, p store.Comparison, value interface{}) bson.D {
	switch p {
	case store.NoComparison:
		return query
	case store.Equal:
		// TODO with Mongo 3.0, we could remove this special case
		// and use $eq instead.
		return append(query, bson.DocElem{fieldName, value})
	default:
		return append(query, bson.DocElem{fieldName, bson.D{{comparisonOps[p], value}}})
	}
}

var comparisonOps = []string{
	store.NotEqual:           "$ne",
	store.GreaterThan:        "$gt",
	store.LessThan:           "$lt",
	store.GreaterThanOrEqual: "$gte",
	store.LessThanOrEqual:    "$lte",
}

// UpdateIdentity implements store.Store.UpdateIdentity by writing the
// identity update to the mongodb database. The given context must have a
// mgo.Session added using ContextWithSession.
func (s *identityStore) UpdateIdentity(ctx context.Context, identity *store.Identity, update store.Update) error {
	coll := s.db.c(ctx, identitiesCollection)
	defer coll.Database.Session.Close()

	if identity.ID == "" && identity.ProviderID != "" {
		return errgo.Mask(s.upsertIdentity(coll, identity, update), errgo.Is(store.ErrDuplicateUsername))
	}
	err := coll.Update(identityQuery(identity), identityUpdate(identity, update))
	if err == nil {
		return nil
	}
	if err == mgo.ErrNotFound {
		return store.NotFoundError(identity.ID, "", identity.Username)
	}
	if mgo.IsDup(err) {
		return store.DuplicateUsernameError(identity.Username)
	}
	return errgo.Mask(err)
}

func (s *identityStore) upsertIdentity(coll *mgo.Collection, identity *store.Identity, update store.Update) error {
	changeInfo, err := coll.Upsert(bson.D{{"providerid", identity.ProviderID}}, identityUpdate(identity, update))
	if err != nil {
		if mgo.IsDup(err) {
			return store.DuplicateUsernameError(identity.Username)
		}
		return errgo.Mask(err)
	}
	id, ok := changeInfo.UpsertedId.(bson.ObjectId)
	if ok {
		identity.ID = id.Hex()
	}
	return nil
}

func identityUpdate(identity *store.Identity, update store.Update) updateDocument {
	var doc updateDocument
	doc.addUpdate(update[store.Username], fieldNames[store.Username], identity.Username)
	doc.addUpdate(update[store.Name], fieldNames[store.Name], identity.Name)
	doc.addUpdate(update[store.Email], fieldNames[store.Email], identity.Email)
	doc.addUpdate(update[store.Groups], fieldNames[store.Groups], identity.Groups)
	doc.addUpdate(update[store.PublicKeys], fieldNames[store.PublicKeys], encodePublicKeys(identity.PublicKeys))
	doc.addUpdate(update[store.LastLogin], fieldNames[store.LastLogin], identity.LastLogin)
	doc.addUpdate(update[store.LastDischarge], fieldNames[store.LastDischarge], identity.LastDischarge)
	for k, v := range identity.ProviderInfo {
		doc.addUpdate(update[store.ProviderInfo], fieldNames[store.ProviderInfo]+"."+k, v)
	}
	for k, v := range identity.ExtraInfo {
		doc.addUpdate(update[store.ExtraInfo], fieldNames[store.ExtraInfo]+"."+k, v)
	}
	return doc
}

func encodePublicKeys(pks []bakery.PublicKey) [][]byte {
	data := make([][]byte, len(pks))
	for i, pk := range pks {
		b, _ := pk.MarshalBinary()
		data[i] = b
	}
	return data
}

func ensureIdentityIndexes(db *mgo.Database) error {
	coll := db.C(identitiesCollection)
	indexes := []mgo.Index{{
		Key:    []string{"username"},
		Unique: true,
	}, {
		Key:    []string{"providerid"},
		Unique: true,
	}}
	for _, index := range indexes {
		if err := coll.EnsureIndex(index); err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}
