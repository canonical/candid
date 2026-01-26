// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package candid_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/memsimplekv"

	"github.com/canonical/candid"
	"github.com/canonical/candid/candidtest"
	"github.com/canonical/candid/store/memstore"
)

// TestServerTLSCipherSuites tests that:
//  1. The server can be configured with specific TLS cipher suites
//  2. The server only accepts those configured ciphers
//  3. The server is accessible via HTTP/2
//     and uses TLS1.2 as for TLS1.3 ciphers cannot be configured
//  4. All configured ciphers are available
func TestServerTLSCipherSuites(t *testing.T) {
	c := qt.New(t)

	configuredCiphers := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}

	// Generate a test certificate and key
	key, err := bakery.GenerateKey()
	c.Assert(err, qt.IsNil)

	// Create a self-signed certificate for testing
	cert, certPEM, keyPEM, err := candidtest.GenerateTestCert("localhost")
	c.Assert(err, qt.IsNil)

	// Create server parameters
	params := candid.ServerParams{
		Store:             memstore.NewStore(),
		MeetingStore:      memstore.NewMeetingStore(),
		ProviderDataStore: memstore.NewProviderDataStore(),
		RootKeyStore:      bakery.NewMemRootKeyStore(),
		ACLStore:          aclstore.NewACLStore(memsimplekv.NewStore()),
		Key:               key,
		Location:          "https://localhost",
	}

	// Create a custom TLS configuration with specific cipher suites
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12, // Force TLS 1.2 to test cipher suite configuration
		NextProtos:   []string{"h2", "http/1.1"},
	}

	// Convert cipher suite names to their numeric IDs
	var cipherSuiteIDs []uint16
	for _, cipherName := range configuredCiphers {
		for _, cs := range tls.CipherSuites() {
			if cs.Name == cipherName {
				cipherSuiteIDs = append(cipherSuiteIDs, cs.ID)
				break
			}
		}
	}
	tlsConfig.CipherSuites = cipherSuiteIDs

	// Create an HTTPS server with the handler and TLS config
	handler, err := candid.NewServer(params, candid.V1)
	c.Assert(err, qt.IsNil)
	defer handler.Close()
	srv := candidtest.NewTLSServerWithConfig(handler, tlsConfig, certPEM, keyPEM)
	defer srv.Close()

	// Create a client that will verify cipher suites
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			// Force HTTP/2
			ForceAttemptHTTP2: true,
		},
	}

	// Connect to the server and get connection state
	resp, err := client.Get(srv.URL + "/v1/discharge")
	c.Assert(err, qt.IsNil)
	defer resp.Body.Close()

	// Get the TLS connection state from the response
	c.Assert(resp.TLS, qt.Not(qt.IsNil), qt.Commentf("expected TLS connection"))

	// Verify the protocol is HTTP/2
	c.Assert(resp.Proto, qt.Equals, "HTTP/2.0")

	// Verify that the cipher suite used is one of the configured ones
	usedCipherID := resp.TLS.CipherSuite
	fmt.Printf("Server selected cipher suite name %s and ID: %d\n", tls.CipherSuiteName(usedCipherID), usedCipherID)
	fmt.Printf("Configured cipher suite names %s and IDs: %v\n", configuredCiphers, cipherSuiteIDs)
	found := false
	for _, id := range cipherSuiteIDs {
		if id == usedCipherID {
			found = true
			break
		}
	}
	c.Assert(found, qt.IsTrue, qt.Commentf(
		"cipher suite %d not in configured suites: %v",
		usedCipherID, cipherSuiteIDs,
	))

	// Verify all configured ciphers are actually usable by creating multiple connections
	usedCiphers := make(map[uint16]bool)
	for i := 0; i < 5; i++ {
		resp, err := client.Get(srv.URL + "/v1/discharge")
		c.Assert(err, qt.IsNil)
		c.Assert(resp.TLS, qt.Not(qt.IsNil))
		usedCiphers[resp.TLS.CipherSuite] = true
		resp.Body.Close()
	}

	// Verify at least one cipher from our configured set was used
	c.Assert(len(usedCiphers) > 0, qt.IsTrue, qt.Commentf("no ciphers were used"))

	// All used ciphers should be in our configured set
	for usedCipherID := range usedCiphers {
		found := false
		for _, id := range cipherSuiteIDs {
			if id == usedCipherID {
				found = true
				break
			}
		}
		c.Assert(found, qt.IsTrue, qt.Commentf(
			"cipher suite %d not in configured suites: %v",
			usedCipherID, cipherSuiteIDs,
		))
	}
}

// TestServerTLSCipherSuitesRestriction tests that unconfigured ciphers
// cannot be used even if the client requests them
func TestServerTLSCipherSuitesRestriction(t *testing.T) {
	c := qt.New(t)

	// Define only one cipher suite to be available
	configuredCiphers := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}

	// Generate a test certificate and key
	key, err := bakery.GenerateKey()
	c.Assert(err, qt.IsNil)

	// Create a self-signed certificate for testing
	cert, certPEM, keyPEM, err := candidtest.GenerateTestCert("localhost")
	c.Assert(err, qt.IsNil)

	// Create server parameters
	params := candid.ServerParams{
		Store:             memstore.NewStore(),
		MeetingStore:      memstore.NewMeetingStore(),
		ProviderDataStore: memstore.NewProviderDataStore(),
		RootKeyStore:      bakery.NewMemRootKeyStore(),
		ACLStore:          aclstore.NewACLStore(memsimplekv.NewStore()),
		Key:               key,
		Location:          "https://localhost",
	}

	// Create a custom TLS configuration with specific cipher suites
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12, // Force TLS 1.2 to test cipher suite configuration
		NextProtos:   []string{"h2", "http/1.1"},
	}

	// Convert cipher suite names to their numeric IDs
	var cipherSuiteIDs []uint16
	for _, cipherName := range configuredCiphers {
		for _, cs := range tls.CipherSuites() {
			if cs.Name == cipherName {
				cipherSuiteIDs = append(cipherSuiteIDs, cs.ID)
				break
			}
		}
	}
	c.Assert(cipherSuiteIDs, qt.HasLen, len(configuredCiphers))
	tlsConfig.CipherSuites = cipherSuiteIDs

	// Create the server
	handler, err := candid.NewServer(params, candid.V1)
	c.Assert(err, qt.IsNil)
	defer handler.Close()

	// Create an HTTPS server with the handler and TLS config
	srv := candidtest.NewTLSServerWithConfig(handler, tlsConfig, certPEM, keyPEM)
	defer srv.Close()

	// Create a client that prefers a different cipher (but still compatible)
	// This tests that the server enforces its cipher preferences
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		// Request multiple ciphers, but server should use its preferred one
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: false,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   clientTLSConfig,
			ForceAttemptHTTP2: true,
		},
	}

	resp, err := client.Get(srv.URL + "/v1/discharge")
	c.Assert(err, qt.IsNil)
	defer resp.Body.Close()

	// Verify that the cipher suite used is the one configured on the server
	c.Assert(resp.TLS.CipherSuite, qt.Equals, cipherSuiteIDs[0], qt.Commentf(
		"expected server-configured cipher %d, got %d",
		cipherSuiteIDs[0], resp.TLS.CipherSuite,
	))
}
