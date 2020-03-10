// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

//go:generate go run generate_certs.go -o certs.go

// Package candidtest provides an inmemory candid service for use in
// tests.
package candidtest

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/memsimplekv"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/canonical/candid"
	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/static"
	"github.com/canonical/candid/meeting"
	"github.com/canonical/candid/store"
	"github.com/canonical/candid/store/memstore"
)

type Server struct {
	// URL contains the URL where the server is listening.
	URL string

	// CACert contains the PEM encoded CA certificate that signed the
	// server's certificate, if the server is using TLS.
	CACert []byte

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
	if err := s.init(users); err != nil {
		return nil, errgo.Mask(err)
	}

	go s.server.Serve(s.listener)
	return s, nil
}

// NewTLS is like New except the listening server will be using TLS.
func NewTLS(users map[string]static.UserInfo) (*Server, error) {
	s := new(Server)

	s.CACert = caCert
	cert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if err := s.init(users); err != nil {
		return nil, errgo.Mask(err)
	}

	s.server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	go s.server.ServeTLS(s.listener, "", "")
	return s, nil
}

func (s *Server) init(users map[string]static.UserInfo) error {
	s.Store = memstore.NewStore()
	s.MeetingStore = memstore.NewMeetingStore()
	s.ProviderDataStore = memstore.NewProviderDataStore()
	s.RootKeyStore = bakery.NewMemRootKeyStore()
	s.ACLStore = aclstore.NewACLStore(memsimplekv.NewStore())
	key, err := bakery.GenerateKey()
	if err != nil {
		return errgo.Mask(err)
	}
	s.AdminAgentKey, err = bakery.GenerateKey()
	if err != nil {
		return errgo.Mask(err)
	}
	staticIDP := static.NewIdentityProvider(static.Params{
		Name:  "static",
		Users: users,
	})
	s.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errgo.Mask(err)
	}
	if s.CACert == nil {
		s.URL = "http://" + s.listener.Addr().String()
	} else {
		s.URL = "https://" + s.listener.Addr().String()
	}
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
		return errgo.Mask(err)
	}
	return nil
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
