// Copyright 2014 Canonical Ltd.

package store

import (
	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
)

// Entities returns the mongo collection where entities are stored.
func (s StoreDatabase) IdentityProviders() *mgo.Collection {
	return s.C("identity_providers")
}

// ListIdentityProviders returns a list of all the registered identity
// provider names.
func (s *Store) IdentityProviderNames() ([]string, error) {
	providers := []string{}
	var idp mongodoc.IdentityProvider
	it := s.DB.IdentityProviders().Find(nil).Select(bson.M{"_id": 1}).Iter()
	for it.Next(&idp) {
		providers = append(providers, idp.Name)
	}
	if err := it.Close(); err != nil {
		return nil, errgo.Notef(err, "cannot retrieve providers")
	}
	return providers, nil
}

// GetIdentityProvider returns the IdentityProvider information describing
// the named identity provider.
func (s *Store) IdentityProvider(p string) (*mongodoc.IdentityProvider, error) {
	var idp mongodoc.IdentityProvider
	if err := s.DB.IdentityProviders().FindId(p).One(&idp); err != nil {
		return nil, errgo.WithCausef(err, err, `cannot get identity provider "%v"`, p)
	}
	return &idp, nil
}

// SetIdentityProvider sets the identity provider specified by p to be the settings
// supplied in idp.
func (s *Store) SetIdentityProvider(idp *mongodoc.IdentityProvider) error {
	if _, err := s.DB.IdentityProviders().UpsertId(idp.Name, idp); err != nil {
		return errgo.Notef(err, `cannot set identity provider "%v"`, idp.Name)
	}
	return nil
}
