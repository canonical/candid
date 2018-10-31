// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore

import (
	"github.com/juju/simplekv"
	"github.com/juju/simplekv/mgosimplekv"
	"golang.org/x/net/context"
)

// an providerDataStore implements store.ProviderDataStore.
type providerDataStore struct {
	backend *backend
}

func (s *providerDataStore) KeyValueStore(ctx context.Context, idp string) (simplekv.Store, error) {
	return mgosimplekv.NewStore(s.backend.db.C("kv" + idp))
}
