// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package memstore

import (
	"bytes"
	"context"
	"fmt"

	errgo "gopkg.in/errgo.v1"

	"github.com/canonical/candid/store"
)

func mfaCredentialKey(cred store.MFACredential) string {
	return fmt.Sprintf("%s-%s", cred.ProviderID, cred.Name)
}

// AddMFACredential stores the specified multi-factor credential.
func (s *memStore) AddMFACredential(ctx context.Context, cred store.MFACredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := mfaCredentialKey(cred)
	_, ok := s.credentials[key]
	if ok {
		return errgo.WithCausef(nil, store.ErrDuplicateCredential, "credential with name %q already exists", cred.Name)
	}
	s.credentials[key] = cred
	return nil
}

// RemoveMFACredential removes the multi-factor credential with the
// specified username and credential name.
func (s *memStore) RemoveMFACredential(ctx context.Context, providerID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := mfaCredentialKey(store.MFACredential{
		ProviderID: store.ProviderIdentity(providerID),
		Name:       name,
	})
	delete(s.credentials, key)
	return nil
}

// UserMFACredentials returns all multi-factor credentials for the specified user.
func (s *memStore) UserMFACredentials(ctx context.Context, providerID string) ([]store.MFACredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var credentials []store.MFACredential
	for _, cred := range s.credentials {
		if string(cred.ProviderID) == providerID {
			credentials = append(credentials, cred)
		}
	}
	return credentials, nil
}

// IncrementMFACredentialSignCount increments the multi-factor credential sign count.
func (s *memStore) IncrementMFACredentialSignCount(ctx context.Context, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, c := range s.credentials {
		if bytes.Compare(c.ID, credentialID) == 0 {
			c.AuthenticatorSignCount++
			s.credentials[key] = c
			break
		}
	}
	return nil
}
