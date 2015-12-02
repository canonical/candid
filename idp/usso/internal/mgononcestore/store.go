// Copyright 2015 Canonical Ltd.

// Package mgononcestore is an openid.NonceStore that is backed by mgo.
package mgononcestore

import (
	"sync/atomic"
	"time"

	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var logger = loggo.GetLogger("idp.usso.internal.mgononcestore")

type Params struct {
	// CollectionName is the name to use for the collection. If this
	// is not set then it will default to "nonces".
	CollectionName string

	// MaxAge is the maximum age of stored nonces. Any nonces older
	// than this will automatically be rejected. Stored nonces older
	// than this will periodically be purged from the database. If
	// this is zero, the default is one minute.
	MaxAge time.Duration
}

type Pool struct {
	params Params
	cnt    uint32
}

// New creates a new Pool.
func New(p Params) *Pool {
	if p.CollectionName == "" {
		p.CollectionName = "nonces"
	}
	if p.MaxAge == 0 {
		p.MaxAge = time.Minute
	}
	return &Pool{
		params: p,
	}
}

// Store gets a Store from the pool. The caller must call Close on the
// returned Store once it is finished with.
func (p *Pool) Store(db *mgo.Database) *Store {
	return &Store{
		pool: p,
		c:    db.C(p.params.CollectionName),
	}
}

// Store is an openid.NonceStore that is backed by mongodb.
type Store struct {
	pool *Pool
	c    *mgo.Collection
}

// Accept implements openid.NonceStore.Accept.
func (s *Store) Accept(endpoint, nonce string) error {
	return s.accept(endpoint, nonce, time.Now())
}

// accept is the implementation of Accept. The third parameter is the
// current time, useful for testing.
func (s *Store) accept(endpoint, nonce string, now time.Time) error {
	// From the openid specification:
	//
	// openid.response_nonce
	//
	// Value: A string 255 characters or less in length, that MUST be
	// unique to this particular successful authentication response.
	// The nonce MUST start with the current time on the server, and
	// MAY contain additional ASCII characters in the range 33-126
	// inclusive (printable non-whitespace characters), as necessary
	// to make each response unique. The date and time MUST be
	// formatted as specified in section 5.6 of [RFC3339], with the
	// following restrictions:
	//
	// + All times must be in the UTC timezone, indicated with a "Z".
	//
	// + No fractional seconds are allowed
	//
	// For example: 2005-05-15T17:11:51ZUNIQUE

	if len(nonce) < 20 {
		return errgo.Newf("%q does not contain a valid timestamp", nonce)
	}
	t, err := time.Parse(time.RFC3339, nonce[:20])
	if err != nil {
		return errgo.Notef(err, "%q does not contain a valid timestamp", nonce)
	}
	if t.Before(now.Add(-s.pool.params.MaxAge)) {
		return errgo.Newf("%q too old", nonce)
	}
	if atomic.AddUint32(&s.pool.cnt, 1)&0xFF == 1 {
		// Garbage collect old records every 256 database
		// accesses. Here old means > 2 * MaxAge, this avoids any
		// race conditions around nonces that are close to timing
		// out. The garbage collection is performed when cnt == 1
		// (mod 256) to ensure it is always run when the identity
		// manager first starts.

		_, err := s.c.RemoveAll(
			bson.D{{"time", bson.D{{"$lt", now.Add(-2 * s.pool.params.MaxAge)}}}},
		)
		if err != nil {
			logger.Warningf("error removing old nonces: %v", err)
		}
	}
	err = s.c.Insert(nonceDoc{
		ID:   endpoint + "#" + nonce,
		Time: t,
	})
	if mgo.IsDup(err) {
		return errgo.Newf("%q already seen for %q", nonce, endpoint)
	}
	return errgo.Mask(err)
}

// Close return the store to the pool.
func (s *Store) Close() {
	s.c = nil
}

// nonceDoc is the document that is stored in mongodb recording that it
// has already been seen.
type nonceDoc struct {
	ID   string    `bson:"_id"`
	Time time.Time `bson:"time"`
}
