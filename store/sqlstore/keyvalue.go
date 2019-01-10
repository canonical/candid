// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sqlstore

import (
	"context"

	"github.com/juju/simplekv"
	"github.com/juju/simplekv/sqlsimplekv"
)

// A providerDataStore implements store.ProviderDataStore.
type providerDataStore struct {
	b *backend
}

func (s *providerDataStore) KeyValueStore(_ context.Context, idp string) (simplekv.Store, error) {
	return sqlsimplekv.NewStore(s.b.driver.name, s.b.db, "idpkv_"+idp)
}
