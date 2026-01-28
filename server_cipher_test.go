// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Note: for TLS 1.3 golang does not allow configuring cipher suites,
// so these tests focus on TLS 1.2.

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

func serverTLSCipherSuitesRunner(t *testing.T, configuredCiphers []string, clientTLSConfig *tls.Config) {
	c := qt.New(t)

	// Generate a test certificate, key, and self-sign
	key, err := bakery.GenerateKey()
	c.Assert(err, qt.IsNil)
	cert, certPEM, keyPEM, err := candidtest.GenerateTestCert("localhost")
	c.Assert(err, qt.IsNil)

	params := candid.ServerParams{
		Store:             memstore.NewStore(),
		MeetingStore:      memstore.NewMeetingStore(),
		ProviderDataStore: memstore.NewProviderDataStore(),
		RootKeyStore:      bakery.NewMemRootKeyStore(),
		ACLStore:          aclstore.NewACLStore(memsimplekv.NewStore()),
		Key:               key,
		Location:          "https://localhost",
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12, // Force TLS 1.2 to test cipher suite configuration
		NextProtos:   []string{"h2", "http/1.1"},
	}

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

	// HTTPS server
	handler, err := candid.NewServer(params, candid.V1)
	c.Assert(err, qt.IsNil)
	defer handler.Close()
	srv := candidtest.NewTLSServerWithConfig(handler, tlsConfig, certPEM, keyPEM)
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   clientTLSConfig,
			ForceAttemptHTTP2: true,
		},
	}

	resp, err := client.Get(srv.URL + "/v1/discharge")
	c.Assert(err, qt.IsNil)
	defer resp.Body.Close()

	c.Assert(resp.TLS, qt.Not(qt.IsNil), qt.Commentf("expected TLS connection"))

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
}

func TestServerTLSCipherSuites(t *testing.T) {
	configuredCiphers := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}

	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	serverTLSCipherSuitesRunner(t, configuredCiphers, clientTLSConfig)
}

func TestServerTLSCipherSuitesRestriction(t *testing.T) {
	// Define only one cipher suite to be available
	configuredCiphers := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}

	// Create a client that prefers a different cipher (but still compatible)
	// This tests that the server enforces its cipher preferences
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			// prefer unconfigured cipher suites
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: false,
	}

	serverTLSCipherSuitesRunner(t, configuredCiphers, clientTLSConfig)
}
