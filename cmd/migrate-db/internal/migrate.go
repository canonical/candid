// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package internal

import (
	"log"
	"strings"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/store"
)

// SplitStoreSpecification splits a store specification string as
// supplied in the command line arguments into a type and address.
func SplitStoreSpecification(s string) (type_, addr string) {
	n := strings.IndexByte(s, ':')
	if n < 0 {
		return s, ""
	}
	return s[:n], s[n+1:]
}

// A Source is the interface that Copy uses to collect migrated
// identitites from.
type Source interface {
	// Next fetches the next identity from the source. Next returns
	// true if the identity was successfully fetched. If there are no
	// more identities, or an error occurs then false is returned,
	// the Err method can be used to determine which.
	Next() bool

	// Identity returns the current identity for the source. The
	// pointer is only valid unti Next is called again.
	Identity() *store.Identity

	// Err returns any error received whilst getting identities.
	Err() error
}

// Copy creates a new identity in dst for every identity retreived from src.
func Copy(ctx context.Context, dst store.Store, src Source) error {
	var failed bool
	update := store.Update{
		store.Username:      store.Set,
		store.Name:          store.Set,
		store.Email:         store.Set,
		store.Groups:        store.Set,
		store.PublicKeys:    store.Set,
		store.LastLogin:     store.Set,
		store.LastDischarge: store.Set,
		store.ProviderInfo:  store.Set,
		store.ExtraInfo:     store.Set,
	}
	for src.Next() {
		identity := src.Identity()
		// The ID field is store specific, so cannot be copied between them.
		identity.ID = ""
		err := dst.UpdateIdentity(ctx, identity, update)
		if err != nil {
			log.Printf("cannot update user %s: %s", identity.Username, err)
			failed = true
		}
	}
	if failed {
		return errgo.Newf("some updates failed")
	}
	if err := src.Err(); err != nil {
		return errgo.Notef(err, "cannot read identities")
	}
	return nil
}

// A StoreSource is a Source that wraps a store.Store.
type StoreSource struct {
	index      int
	identities []store.Identity
	err        error
}

// NewStoreSource creates a new StoreSource that use the given store for
// its source of identities.
func NewStoreSource(ctx context.Context, st store.Store) *StoreSource {
	ctx, close := st.Context(ctx)
	defer close()
	identities, err := st.FindIdentities(ctx, nil, store.Filter{}, nil, 0, 0)
	return &StoreSource{
		identities: identities,
		err:        err,
	}
}

// Next implements Source.Next.
func (s *StoreSource) Next() bool {
	if s.err != nil {
		return false
	}
	s.index++
	if s.index > len(s.identities) {
		return false
	}
	return true
}

// Identity implements Source.Identity.
func (s *StoreSource) Identity() *store.Identity {
	return &s.identities[s.index-1]
}

// Err implements Source.Err.
func (s *StoreSource) Err() error {
	return s.err
}
