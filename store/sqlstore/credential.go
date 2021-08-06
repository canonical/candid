// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sqlstore

import (
	"context"

	errgo "gopkg.in/errgo.v1"

	"github.com/canonical/candid/store"
)

type userCredentialParams struct {
	argBuilder

	ProviderID             store.ProviderIdentity
	Name                   string
	ID                     []byte
	PublicKey              []byte
	AttestationType        string
	AuthenticatorGUID      []byte
	AuthenticatorSignCount uint32
}

// AddMFACredential stores the specified multi-factor credential.
func (s *identityStore) AddMFACredential(ctx context.Context, cred store.MFACredential) error {
	params := &userCredentialParams{
		argBuilder:             s.driver.argBuilderFunc(),
		ProviderID:             cred.ProviderID,
		Name:                   cred.Name,
		ID:                     cred.ID,
		PublicKey:              cred.PublicKey,
		AttestationType:        cred.AttestationType,
		AuthenticatorGUID:      cred.AuthenticatorGUID,
		AuthenticatorSignCount: cred.AuthenticatorSignCount,
	}
	_, err := s.driver.exec(s.db, tmplInsertUserCredentials, params)
	if err != nil {
		if postgresIsDuplicate(errgo.Cause(err)) {
			return errgo.WithCausef(nil, store.ErrDuplicateCredential, "credential with name %q already exists", cred.Name)
		}
		return errgo.Mask(err)
	}
	return nil
}

// RemoveMFACredential removes the multi-factor credential with the
// specified username and credential name.
func (s *identityStore) RemoveMFACredential(ctx context.Context, providerID, name string) error {
	params := &userCredentialParams{
		argBuilder: s.driver.argBuilderFunc(),
		ProviderID: store.ProviderIdentity(providerID),
		Name:       name,
	}
	_, err := s.driver.exec(s.db, tmplRemoveUserCredentials, params)
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// UserMFACredentials returns all multi-factor credentials for the specified user.
func (s *identityStore) UserMFACredentials(ctx context.Context, providerID string) ([]store.MFACredential, error) {
	params := &userCredentialParams{
		argBuilder: s.driver.argBuilderFunc(),
		ProviderID: store.ProviderIdentity(providerID),
	}
	rows, err := s.driver.query(s.db, tmplGetUserCredentials, params)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer rows.Close()
	var credentials []store.MFACredential
	for rows.Next() {
		var cred store.MFACredential
		if err := rows.Scan(&cred.ID,
			&cred.ProviderID,
			&cred.Name,
			&cred.PublicKey,
			&cred.AttestationType,
			&cred.AuthenticatorGUID,
			&cred.AuthenticatorSignCount,
		); err != nil {
			return nil, errgo.Mask(err)
		}
		credentials = append(credentials, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, errgo.Mask(err)
	}
	return credentials, nil
}

// IncrementMFACredentialSignCount increments the multi-factor credential sign count.
func (s *identityStore) IncrementMFACredentialSignCount(ctx context.Context, credentialID []byte) error {
	params := &userCredentialParams{
		argBuilder: s.driver.argBuilderFunc(),
		ID:         credentialID,
	}
	_, err := s.driver.exec(s.db, tmplIncrementCredentialSignCount, params)
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}
