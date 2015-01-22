// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"net/http"

	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v0/bakery"
	"gopkg.in/macaroon-bakery.v0/bakery/mgostorage"
	"gopkg.in/macaroon.v1"
	"gopkg.in/mgo.v2"

	"github.com/CanonicalLtd/blues-identity/internal/idtesting"
	"github.com/CanonicalLtd/blues-identity/internal/server"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/internal/v1"
	"github.com/CanonicalLtd/blues-identity/params"
)

const (
	version       = "v1"
	adminUsername = "admin"
	adminPassword = "password"
)

type apiSuite struct {
	idtesting.IsolatedMgoSuite
	srv     http.Handler
	store   *store.Store
	keyPair *bakery.KeyPair
	svc     *bakery.Service
}

var _ = gc.Suite(&apiSuite{})

func (s *apiSuite) SetUpSuite(c *gc.C) {
	s.IsolatedMgoSuite.SetUpSuite(c)
}

func (s *apiSuite) TearDownSuite(c *gc.C) {
	s.IsolatedMgoSuite.TearDownSuite(c)
}

func (s *apiSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.srv, s.store = newServer(c, s.Session, key)
	// Create Macaroon storage.
	ms, err := mgostorage.New(s.store.DB.Macaroons())
	c.Assert(err, gc.IsNil)

	// Create the bakery Service.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Store: ms,
		Key:   key,
	})
	c.Assert(err, gc.IsNil)
	s.svc = svc
	s.keyPair = key
}

func (s *apiSuite) TearDownTest(c *gc.C) {
	s.IsolatedMgoSuite.TearDownTest(c)
}

func newServer(c *gc.C, session *mgo.Session, key *bakery.KeyPair) (http.Handler, *store.Store) {
	db := session.DB("testing")
	store, err := store.New(db)
	c.Assert(err, gc.IsNil)
	srv, err := server.New(
		db,
		server.ServerParams{
			AuthUsername: adminUsername,
			AuthPassword: adminPassword,
			Key:          key,
		},
		map[string]server.NewAPIHandlerFunc{
			version: v1.NewAPIHandler,
		},
	)
	c.Assert(err, gc.IsNil)
	return srv, store
}

func (s *apiSuite) assertMacaroon(c *gc.C, ms macaroon.Slice, check bakery.FirstPartyChecker) {
	err := s.svc.Check(ms, check)
	c.Assert(err, gc.IsNil)
}

func (s *apiSuite) createUser(c *gc.C, user *params.User) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/" + user.UserName),
		Method:  "PUT",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:         marshal(c, user),
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
		ExpectBody:   user,
	})
}

func apiURL(path string) string {
	return "/" + version + "/" + path
}
