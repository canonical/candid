// Copyright 2015 Canonical Ltd.

package mgononcestore_test

import (
	"fmt"
	"time"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/yohcop/openid-go"
	gc "gopkg.in/check.v1"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/mgononcestore"
)

var _ openid.NonceStore = (*mgononcestore.Store)(nil)

type storeSuite struct {
	testing.IsolatedMgoSuite
	pool  *mgononcestore.Pool
	store *mgononcestore.Store
}

var _ = gc.Suite(&storeSuite{})

func (s *storeSuite) SetUpSuite(c *gc.C) {
	s.IsolatedMgoSuite.SetUpSuite(c)
	s.pool = mgononcestore.New(mgononcestore.Params{})
}

func (s *storeSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	s.store = s.pool.Store(s.Session.DB("test"))
}

func (s *storeSuite) TearDownTest(c *gc.C) {
	s.store.Close()
	s.store = nil
	s.IsolatedMgoSuite.TearDownTest(c)
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
	err = mgononcestore.Accept(s.store, "https://example.com", "2014-12-25T00:00:00Z0", now)
	c.Assert(err, gc.IsNil)
	for i, test := range acceptTests {
		c.Logf("%d. %s", i, test.about)
		err := mgononcestore.Accept(s.store, test.endpoint, test.nonce, now)
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			continue
		}
		c.Assert(err, gc.IsNil)
	}
}

func (s *storeSuite) TestGC(c *gc.C) {
	now, err := time.Parse(time.RFC3339, "2014-12-25T00:00:00Z")
	c.Assert(err, gc.IsNil)
	db := s.Session.DB("gctest")
	coll := db.C("nonces")
	nonces := []struct {
		endpoint, nonce string
	}{{
		"https://example.com", "2014-12-25T00:00:00Z0",
	}, {
		"https://example.com/2", "2014-12-25T00:00:00Z0",
	}, {
		"https://example.com", "2013-12-25T00:00:00Z0",
	}, {
		"https://example.com", "2014-12-24T23:59:00Z0",
	}, {
		"https://example.com", "2014-12-24T23:58:00Z0",
	}, {
		"https://example.com/2", "2014-12-24T23:57:59Z0",
	}}
	for _, n := range nonces {
		t, err := time.Parse(time.RFC3339, n.nonce[:20])
		c.Assert(err, gc.IsNil)
		err = coll.Insert(mgononcestore.NonceDoc{
			ID:   fmt.Sprintf("%s#%s", n.endpoint, n.nonce),
			Time: t,
		})
		c.Assert(err, gc.IsNil)
	}
	pool := mgononcestore.New(mgononcestore.Params{})
	store := pool.Store(db)
	err = mgononcestore.Accept(
		store,
		"https://example.com",
		"2014-12-25T00:00:00Z1",
		now,
	)
	c.Assert(err, gc.IsNil)
	var result []mgononcestore.NonceDoc
	err = coll.Find(nil).Sort("_id").Select(bson.D{{"_id", 1}}).All(&result)
	c.Assert(err, gc.IsNil)
	c.Assert(result, jc.DeepEquals, []mgononcestore.NonceDoc{{
		ID: "https://example.com#2014-12-24T23:58:00Z0",
	}, {
		ID: "https://example.com#2014-12-24T23:59:00Z0",
	}, {
		ID: "https://example.com#2014-12-25T00:00:00Z0",
	}, {
		ID: "https://example.com#2014-12-25T00:00:00Z1",
	}, {
		ID: "https://example.com/2#2014-12-25T00:00:00Z0",
	}})
}
