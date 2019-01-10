// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package kvnoncestore_test

import (
	"context"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/yohcop/openid-go"

	"github.com/CanonicalLtd/candid/idp/usso/internal/kvnoncestore"
	"github.com/CanonicalLtd/candid/internal/candidtest"
)

var _ openid.NonceStore = (*kvnoncestore.Store)(nil)

var acceptTests = []struct {
	about       string
	endpoint    string
	nonce       string
	expectError string
}{{
	about:    "not seen",
	endpoint: "https://example.com",
	nonce:    "2014-12-25T00:00:00Z1",
}, {
	about:       "seen before",
	endpoint:    "https://example.com",
	nonce:       "2014-12-25T00:00:00Z0",
	expectError: `"2014-12-25T00:00:00Z0" already seen for "https://example.com"`,
}, {
	about:    "seen at another endpoint",
	endpoint: "https://example.com/2",
	nonce:    "2014-12-25T00:00:00Z0",
}, {
	about:       "empty nonce",
	endpoint:    "https://example.com",
	nonce:       "",
	expectError: `"" does not contain a valid timestamp`,
}, {
	about:       "bad nonce",
	endpoint:    "https://example.com",
	nonce:       "1234",
	expectError: `"1234" does not contain a valid timestamp`,
}, {
	about:       "bad time",
	endpoint:    "https://example.com",
	nonce:       "2015/12/25 00:00:00Z1",
	expectError: `"2015/12/25 00:00:00Z1" does not contain a valid timestamp: parsing time "2015/12/25 00:00:00Z" as "2006-01-02T15:04:05Z07:00": cannot parse "/12/25 00:00:00Z" as "-"`,
}, {
	about:       "too old",
	endpoint:    "https://example.com",
	nonce:       "2014-12-24T23:58:59Z0",
	expectError: `"2014-12-24T23:58:59Z0" too old`,
}}

func TestAccept(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	kv, err := candidtest.NewStore().ProviderDataStore.KeyValueStore(context.Background(), "test")
	c.Assert(err, qt.Equals, nil)
	store := kvnoncestore.New(kv, time.Minute)

	now, err := time.Parse(time.RFC3339, "2014-12-25T00:00:00Z")
	c.Assert(err, qt.Equals, nil)
	err = kvnoncestore.Accept(store, "https://example.com", "2014-12-25T00:00:00Z0", now)
	c.Assert(err, qt.Equals, nil)
	for i, test := range acceptTests {
		c.Run(test.about, func(c *qt.C) {
			c.Logf("%d. %s", i, test.about)
			err := kvnoncestore.Accept(store, test.endpoint, test.nonce, now)
			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				return
			}
			c.Assert(err, qt.Equals, nil)
		})
	}
}
