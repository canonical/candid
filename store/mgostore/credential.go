// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore

import (
	"context"

	"github.com/canonical/candid/store"
	"gopkg.in/errgo.v1"
	"github.com/juju/mgo/v2"
	"github.com/juju/mgo/v2/bson"
)

type credentialDoc struct {
	Id                     []byte                 `bson:"_id"`
	ProviderID             store.ProviderIdentity `bson:"provider-id"`
	Name                   string                 `bson:"name"`
	PublicKey              []byte                 `bson:"public-key"`
	AttestationType        string                 `bson:"attestation-type"`
	AuthenticatorGUID      []byte                 `bson:"authenticator-guid"`
	AuthenticatorSignCount uint32                 `bson:"authenticator-sign-count"`
}

const credentialCollection = "credential"

// AddMFACredential stores the specified multi-factor credential.
func (s *identityStore) AddMFACredential(ctx context.Context, cred store.MFACredential) error {
	coll := s.b.c(ctx, credentialCollection)
	defer coll.Database.Session.Close()

	err := coll.Insert(&credentialDoc{
		Id:                     cred.ID,
		ProviderID:             cred.ProviderID,
		Name:                   cred.Name,
		PublicKey:              cred.PublicKey,
		AttestationType:        cred.AttestationType,
		AuthenticatorGUID:      cred.AuthenticatorGUID,
		AuthenticatorSignCount: cred.AuthenticatorSignCount,
	})
	if err != nil {
		if mgo.IsDup(err) {
			return errgo.WithCausef(nil, store.ErrDuplicateCredential, "credential with name %q already exists", cred.Name)
		}
		return errgo.Mask(err)
	}
	return nil

}

// RemoveMFACredential removes the multi-factor credential with the
// specified identity-id and credential name.
func (s *identityStore) RemoveMFACredential(ctx context.Context, providerID, name string) error {
	coll := s.b.c(ctx, credentialCollection)
	defer coll.Database.Session.Close()

	err := coll.Remove(bson.M{"provider-id": store.ProviderIdentity(providerID), "name": name})
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// ClearMFACredentials removes all multi-factor credentials for the specified user.
func (s *identityStore) ClearMFACredentials(ctx context.Context, providerID string) error {
	coll := s.b.c(ctx, credentialCollection)
	defer coll.Database.Session.Close()

	_, err := coll.RemoveAll(bson.M{"provider-id": store.ProviderIdentity(providerID)})
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// UserMFACredentials returns all multi-factor credentials for the specified user.
func (s *identityStore) UserMFACredentials(ctx context.Context, providerID string) ([]store.MFACredential, error) {
	coll := s.b.c(ctx, credentialCollection)
	defer coll.Database.Session.Close()

	q := coll.Find(bson.M{"provider-id": providerID})
	it := q.Iter()
	var credentials []store.MFACredential
	var doc credentialDoc
	for it.Next(&doc) {
		credentials = append(credentials, store.MFACredential{
			ID:                     doc.Id,
			ProviderID:             doc.ProviderID,
			Name:                   doc.Name,
			PublicKey:              doc.PublicKey,
			AttestationType:        doc.AttestationType,
			AuthenticatorGUID:      doc.AuthenticatorGUID,
			AuthenticatorSignCount: doc.AuthenticatorSignCount,
		})
	}
	if err := it.Err(); err != nil {
		return nil, errgo.Mask(err)
	}
	return credentials, nil
}

// IncrementMFACredentialSignCount increments the multi-factor credential sign count.
func (s *identityStore) IncrementMFACredentialSignCount(ctx context.Context, credentialID []byte) error {
	coll := s.b.c(ctx, credentialCollection)
	defer coll.Database.Session.Close()

	err := coll.Update(bson.M{"_id": credentialID}, bson.M{"$inc": bson.M{"authenticator-sign-count": 1}})
	if err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return errgo.WithCausef(nil, store.ErrNotFound, "credential not found")
		}
		return errgo.Mask(err)
	}
	return nil
}

func ensureCredentialsIndexes(db *mgo.Database) error {
	coll := db.C(credentialCollection)
	indexes := []mgo.Index{{
		Key:    []string{"provider-id", "name"},
		Unique: true,
	}}
	for _, index := range indexes {
		if err := coll.EnsureIndex(index); err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}
