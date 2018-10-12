// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package candidtest provides an inmemory candid service for use in
// tests.
package candidtest

import (
	"net"
	"net/http"

	"github.com/juju/aclstore"
	"github.com/juju/simplekv/memsimplekv"
	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/candid"
	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/static"
	"github.com/CanonicalLtd/candid/meeting"
	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/memstore"
)

type Server struct {
	// URL contains the URL where the server is listening.
	URL string

	// AdminAgentKey contains the key required to authenticate as the
	// admin agent.
	AdminAgentKey *bakery.KeyPair

	// The following fields give access to the stores used by the
	// candid server.
	Store             store.Store
	MeetingStore      meeting.Store
	ProviderDataStore store.ProviderDataStore
	RootKeyStore      bakery.RootKeyStore
	ACLStore          aclstore.ACLStore

	listener net.Listener
	server   *http.Server
}

// New creates a new candid server for use in tests. The server will use
// a static IDP with the given set of users. The server must be closed
// when finished with.
func New(users map[string]static.UserInfo) (*Server, error) {
	s := new(Server)
	s.Store = memstore.NewStore()
	s.MeetingStore = memstore.NewMeetingStore()
	s.ProviderDataStore = memstore.NewProviderDataStore()
	s.RootKeyStore = bakery.NewMemRootKeyStore()
	s.ACLStore = aclstore.NewACLStore(memsimplekv.NewStore())
	key, err := bakery.GenerateKey()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	s.AdminAgentKey, err = bakery.GenerateKey()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	staticIDP := static.NewIdentityProvider(static.Params{
		Name:  "static",
		Users: users,
	})
	s.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, errgo.Mask(err)
	}
	s.URL = "http://" + s.listener.Addr().String()
	s.server = new(http.Server)
	s.server.Handler, err = candid.NewServer(candid.ServerParams{
		MeetingStore:      s.MeetingStore,
		ProviderDataStore: s.ProviderDataStore,
		RootKeyStore:      s.RootKeyStore,
		Store:             s.Store,
		ACLStore:          s.ACLStore,
		Key:               key,
		Location:          s.URL,
		IdentityProviders: []idp.IdentityProvider{
			staticIDP,
		},
		AdminAgentPublicKey: &s.AdminAgentKey.Public,
		PrivateAddr:         "127.0.0.1",
	}, candid.Debug, candid.Discharger, candid.V1)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	go s.run()
	return s, nil
}

func (s *Server) run() {
	s.server.Serve(s.listener)
}

// AddIdentity adds a new identity to the server.
func (s *Server) AddIdentity(ctx context.Context, identity *store.Identity) {
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
	if err := s.Store.UpdateIdentity(ctx, identity, update); err != nil {
		panic(err)
	}
}

// Close closes the server.
func (s *Server) Close() error {
	if err := s.server.Shutdown(context.Background()); err != nil {
		return errgo.Mask(err)
	}
	s.server.Handler.(candid.HandlerCloser).Close()
	return nil
}
