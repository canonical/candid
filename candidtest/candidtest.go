// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package candidtest provides an inmemory candid service for use in
// tests.
package candidtest

import (
	"context"
	"net/http/httptest"

	"github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/memsimplekv"
	"gopkg.in/macaroon-bakery.v3/bakery"

	"gopkg.in/canonical/candid.v2"
	"gopkg.in/canonical/candid.v2/store"
	"gopkg.in/canonical/candid.v2/store/memstore"
)

type Testing interface {
	// Cleanup is used to cleanup reseourcs created as part of the test.
	Cleanup(func())

	// Fatalf is used to stop the test when a fatal error occurs.
	Fatalf(f string, args ...interface{})
}

// Serve starts a new candid server using the given parameters. Any
// required parameters that are not spedified will use appropriate
// defaults. The given API versions will be added to the server, if no
// API versions are specified then all available versions will be used.
// Serve uses the Cleanup method on the given Testing object to defer
// cleaning up any reseources that it creates.
func Serve(t Testing, p candid.ServerParams, versions ...string) *httptest.Server {
	srv := httptest.NewUnstartedServer(nil)
	if p.Location == "" {
		p.Location = "http://" + srv.Listener.Addr().String()
	}
	srv.Config.Handler = initServer(t, p, versions...)
	srv.Start()
	return srv
}

// ServeTLS starts a new candid server using the given parameters on a
// TLS server. Any required parameters that are not spedified will use
// appropriate defaults. The given API versions will be added to the
// server, if no API versions are specified then all available versions
// will be used. Serve uses the Cleanup method on the given Testing
// object to defer cleaning up any reseources that it creates.
func ServeTLS(t Testing, p candid.ServerParams, versions ...string) *httptest.Server {
	srv := httptest.NewUnstartedServer(nil)
	if p.Location == "" {
		p.Location = "https://" + srv.Listener.Addr().String()
	}
	srv.Config.Handler = initServer(t, p, versions...)
	srv.StartTLS()
	return srv
}

func initServer(t Testing, p candid.ServerParams, versions ...string) candid.HandlerCloser {
	if p.MeetingStore == nil {
		p.MeetingStore = memstore.NewMeetingStore()
	}
	if p.ProviderDataStore == nil {
		p.ProviderDataStore = memstore.NewProviderDataStore()
	}
	if p.RootKeyStore == nil {
		p.RootKeyStore = bakery.NewMemRootKeyStore()
	}
	if p.Store == nil {
		p.Store = memstore.NewStore()
	}
	if p.Key == nil {
		var err error
		p.Key, err = bakery.GenerateKey()
		if err != nil {
			t.Fatalf("cannot generate key: %s", err)
		}
	}
	if p.ACLStore == nil {
		p.ACLStore = aclstore.NewACLStore(memsimplekv.NewStore())
	}
	if p.PrivateAddr == "" {
		p.PrivateAddr = "127.0.0.1"
	}

	if len(versions) == 0 {
		versions = candid.Versions()
	}

	hnd, err := candid.NewServer(p, versions...)
	if err != nil {
		t.Fatalf("cannot create server: %s", err)
	}

	t.Cleanup(hnd.Close)
	return hnd
}

// AddIdentity adds a new identity to the given store. If there is an
// error adding the identity AddIdentity will panic.
func AddIdentity(ctx context.Context, st store.Store, identity *store.Identity) {
	update := store.Update{
		store.Username: store.Set,
	}
	if identity.Name != "" {
		update[store.Name] = store.Set
	}
	if identity.Email != "" {
		update[store.Email] = store.Set
	}
	if len(identity.Groups) > 0 {
		update[store.Groups] = store.Set
	}
	if len(identity.PublicKeys) > 0 {
		update[store.PublicKeys] = store.Set
	}
	if !identity.LastLogin.IsZero() {
		update[store.LastLogin] = store.Set
	}
	if !identity.LastDischarge.IsZero() {
		update[store.LastDischarge] = store.Set
	}
	if len(identity.ProviderInfo) > 0 {
		update[store.ProviderInfo] = store.Set
	}
	if len(identity.ExtraInfo) > 0 {
		update[store.ExtraInfo] = store.Set
	}
	if identity.Owner != "" {
		update[store.Owner] = store.Set
	}
	if err := st.UpdateIdentity(ctx, identity, update); err != nil {
		panic(err)
	}
}
