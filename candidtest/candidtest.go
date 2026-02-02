// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package candidtest provides an inmemory candid service for use in
// tests.
package candidtest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/memsimplekv"

	"github.com/canonical/candid"
	"github.com/canonical/candid/store"
	"github.com/canonical/candid/store/memstore"
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

// GenerateTestCert generates a self-signed test certificate and returns
// the certificate, certificate PEM, and key PEM.
func GenerateTestCert(commonName string) (tls.Certificate, []byte, []byte, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}

	// Create certificate
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:    []string{commonName, "localhost"},
	}

	// Self-sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Encode private key to PEM
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Create tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
// NewTLSServerWithConfig creates a new TLS HTTPS server with the given handler,
// TLS configuration, and certificate/key PEM data.
func NewTLSServerWithConfig(handler http.Handler, tlsConfig *tls.Config, certPEM, keyPEM []byte) *httptest.Server {
	srv := httptest.NewUnstartedServer(handler)

	// Parse the certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	// Ensure the TLS config has the certificate
	if tlsConfig.Certificates == nil {
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Enable HTTP/2 by setting NextProtos
	if tlsConfig.NextProtos == nil {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}

	srv.TLS = tlsConfig
	srv.StartTLS()
	return srv
}
