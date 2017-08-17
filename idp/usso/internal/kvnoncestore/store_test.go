// Copyright 2015 Canonical Ltd.

package kvnoncestore_test

import (
	"time"

	"github.com/yohcop/openid-go"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/kvnoncestore"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
)

var _ openid.NonceStore = (*kvnoncestore.Store)(nil)

type storeSuite struct {
	idmtest.StoreSuite
	store *kvnoncestore.Store
}

var _ = gc.Suite(&storeSuite{})

func (s *storeSuite) SetUpTest(c *gc.C) {
	s.StoreSuite.SetUpTest(c)
	kv, err := s.ProviderDataStore.KeyValueStore(context.Background(), "test")
	c.Assert(err, gc.Equals, nil)
	s.store = kvnoncestore.New(kv, time.Minute)
}

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

func (s *storeSuite) TestAccept(c *gc.C) {
	now, err := time.Parse(time.RFC3339, "2014-12-25T00:00:00Z")
	c.Assert(err, gc.IsNil)
	err = kvnoncestore.Accept(s.store, "https://example.com", "2014-12-25T00:00:00Z0", now)
	c.Assert(err, gc.IsNil)
	for i, test := range acceptTests {
		c.Logf("%d. %s", i, test.about)
		err := kvnoncestore.Accept(s.store, test.endpoint, test.nonce, now)
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			continue
		}
		c.Assert(err, gc.IsNil)
	}
}
