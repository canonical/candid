// Copyright 2017 Canonical Ltd.

package v1_test

import (
	"net/http"

	"github.com/juju/idmclient/params"
	"github.com/juju/testing"
	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/mgo.v2"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/internal/v1"
)

type idpSuite struct {
	testing.IsolatedMgoSuite
	pool *store.Pool
	hnd  *v1.Handler
}

var _ = gc.Suite(&idpSuite{})

func (s *idpSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.hnd, s.pool = s.newHandler(c, s.Session, key)
}

func (s *idpSuite) TearDownTest(c *gc.C) {
	s.pool.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

func (s *idpSuite) newHandler(c *gc.C, session *mgo.Session, key *bakery.KeyPair) (*v1.Handler, *store.Pool) {
	db := session.DB("testing")
	sp := identity.ServerParams{
		AuthUsername:   adminUsername,
		AuthPassword:   adminPassword,
		Key:            key,
		Location:       location,
		MaxMgoSessions: 50,
		PrivateAddr:    "localhost",
	}
	pool, err := store.NewPool(db, store.StoreParams{
		AuthUsername:   sp.AuthUsername,
		AuthPassword:   sp.AuthPassword,
		Key:            sp.Key,
		Location:       sp.Location,
		MaxMgoSessions: sp.MaxMgoSessions,
		PrivateAddr:    sp.PrivateAddr,
	})
	c.Assert(err, gc.IsNil)
	hnd := v1.New(pool, sp)
	return hnd, pool
}

func (s *idpSuite) idpHandler(idp idp.IdentityProvider) httprouter.Handle {
	return v1.NewIDPHandler(s.hnd, idp)
}

func (s *idpSuite) TestNewIDPHandler(c *gc.C) {
	idp := &testIDP{
		c: c,
	}
	hnd := s.idpHandler(idp)
	c.Assert(hnd, gc.Not(gc.IsNil))
}

func (s *idpSuite) TestURL(c *gc.C) {
	tidp := &testIDP{
		c:    c,
		name: "url-test",
	}
	var hasRun bool
	tidp.handle = func(ctx idp.RequestContext, _ http.ResponseWriter, _ *http.Request) {
		hasRun = true
		c.Check(ctx.URL("/path"), gc.Equals, location+"/v1/idp/url-test/path")
	}
	hnd := s.idpHandler(tidp)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	hnd(nil, req, nil)
	c.Assert(hasRun, gc.Equals, true)
}

func (s *idpSuite) TestRequestURL(c *gc.C) {
	tidp := &testIDP{
		c:    c,
		name: "url-test",
	}
	var hasRun bool
	tidp.handle = func(ctx idp.RequestContext, _ http.ResponseWriter, _ *http.Request) {
		hasRun = true
		c.Check(ctx.RequestURL(), gc.Equals, location)
	}
	hnd := s.idpHandler(tidp)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	hnd(nil, req, nil)
	c.Assert(hasRun, gc.Equals, true)
}

func (s *idpSuite) TestBakery(c *gc.C) {
	tidp := &testIDP{
		c:    c,
		name: "url-test",
	}
	var hasRun bool
	tidp.handle = func(ctx idp.RequestContext, _ http.ResponseWriter, _ *http.Request) {
		hasRun = true
		c.Check(ctx.Bakery(), gc.Not(gc.Equals), nil)
	}
	hnd := s.idpHandler(tidp)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	hnd(nil, req, nil)
	c.Assert(hasRun, gc.Equals, true)
}

func (s *idpSuite) TestDatabase(c *gc.C) {
	tidp := &testIDP{
		c:    c,
		name: "url-test",
	}
	var hasRun bool
	tidp.handle = func(ctx idp.RequestContext, _ http.ResponseWriter, _ *http.Request) {
		hasRun = true
		c.Check(ctx.Database(), gc.Not(gc.Equals), nil)
	}
	hnd := s.idpHandler(tidp)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	hnd(nil, req, nil)
	c.Assert(hasRun, gc.Equals, true)
}

func (s *idpSuite) TestUpdateUser(c *gc.C) {
	tidp := &testIDP{
		c:    c,
		name: "url-test",
	}
	var hasRun bool
	tidp.handle = func(ctx idp.RequestContext, _ http.ResponseWriter, _ *http.Request) {
		hasRun = true
		err := ctx.UpdateUser(&params.User{
			Username:   "test",
			ExternalID: "https://example.com/test",
		})
		c.Check(err, gc.Equals, nil)
		u, err := ctx.FindUserByName("test")
		c.Check(err, gc.Equals, nil)
		c.Check(u.Username, gc.Equals, params.Username("test"))
		c.Check(u.ExternalID, gc.Equals, "https://example.com/test")
	}
	hnd := s.idpHandler(tidp)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	hnd(nil, req, nil)
	c.Assert(hasRun, gc.Equals, true)
}

func (s *idpSuite) TestUpdateUserBadUsername(c *gc.C) {
	tidp := &testIDP{
		c:    c,
		name: "url-test",
	}
	var hasRun bool
	tidp.handle = func(ctx idp.RequestContext, _ http.ResponseWriter, _ *http.Request) {
		hasRun = true
		err := ctx.UpdateUser(&params.User{
			Username:   "test-",
			ExternalID: "https://example.com/test",
		})
		c.Check(err, gc.ErrorMatches, `invalid username "test-"`)
	}
	hnd := s.idpHandler(tidp)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	hnd(nil, req, nil)
	c.Assert(hasRun, gc.Equals, true)
}

func (s *idpSuite) TestFindUserByName(c *gc.C) {
	tidp := &testIDP{
		c:    c,
		name: "url-test",
	}
	var hasRun bool
	tidp.handle = func(ctx idp.RequestContext, _ http.ResponseWriter, _ *http.Request) {
		hasRun = true
		err := ctx.UpdateUser(&params.User{
			Username:   "test",
			ExternalID: "https://example.com/test",
		})
		c.Check(err, gc.Equals, nil)
		u, err := ctx.FindUserByName("test")
		c.Check(err, gc.Equals, nil)
		c.Check(u.Username, gc.Equals, params.Username("test"))
		c.Check(u.ExternalID, gc.Equals, "https://example.com/test")
	}
	hnd := s.idpHandler(tidp)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	hnd(nil, req, nil)
	c.Assert(hasRun, gc.Equals, true)
}

func (s *idpSuite) TestFindUserByNameNoUser(c *gc.C) {
	tidp := &testIDP{
		c:    c,
		name: "url-test",
	}
	var hasRun bool
	tidp.handle = func(ctx idp.RequestContext, _ http.ResponseWriter, _ *http.Request) {
		hasRun = true
		_, err := ctx.FindUserByName("test")
		c.Check(err, gc.ErrorMatches, `user "test" not found: not found`)
		c.Check(errgo.Cause(err), gc.Equals, params.ErrNotFound)
	}
	hnd := s.idpHandler(tidp)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	hnd(nil, req, nil)
	c.Assert(hasRun, gc.Equals, true)
}

func (s *idpSuite) TestFindUserByExternalID(c *gc.C) {
	tidp := &testIDP{
		c:    c,
		name: "url-test",
	}
	var hasRun bool
	tidp.handle = func(ctx idp.RequestContext, _ http.ResponseWriter, _ *http.Request) {
		hasRun = true
		err := ctx.UpdateUser(&params.User{
			Username:   "test",
			ExternalID: "https://example.com/test",
		})
		c.Check(err, gc.Equals, nil)
		u, err := ctx.FindUserByExternalId("https://example.com/test")
		c.Check(err, gc.Equals, nil)
		c.Check(u.Username, gc.Equals, params.Username("test"))
		c.Check(u.ExternalID, gc.Equals, "https://example.com/test")
	}
	hnd := s.idpHandler(tidp)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	hnd(nil, req, nil)
	c.Assert(hasRun, gc.Equals, true)
}

func (s *idpSuite) TestFindUserByExternalIDNoUser(c *gc.C) {
	tidp := &testIDP{
		c:    c,
		name: "url-test",
	}
	var hasRun bool
	tidp.handle = func(ctx idp.RequestContext, _ http.ResponseWriter, _ *http.Request) {
		hasRun = true
		_, err := ctx.FindUserByExternalId("https://example.com/test")
		c.Check(err, gc.ErrorMatches, `not found`)
		c.Check(errgo.Cause(err), gc.Equals, params.ErrNotFound)
	}
	hnd := s.idpHandler(tidp)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	hnd(nil, req, nil)
	c.Assert(hasRun, gc.Equals, true)
}

func (s *idpSuite) TestInit(c *gc.C) {
	var hasRun bool
	tidp := &testIDP{
		c:    c,
		name: "test",
		init: func(ctx idp.Context) error {
			hasRun = true
			return nil
		},
	}
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	_, err = v1.NewAPIHandler(s.pool, identity.ServerParams{
		AuthUsername:   adminUsername,
		AuthPassword:   adminPassword,
		Key:            key,
		Location:       location,
		MaxMgoSessions: 50,
		PrivateAddr:    "localhost",
		IdentityProviders: []idp.IdentityProvider{
			tidp,
		},
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(hasRun, gc.Equals, true)
}

func (s *idpSuite) TestInitError(c *gc.C) {
	var hasRun bool
	tidp := &testIDP{
		c:    c,
		name: "test",
		init: func(ctx idp.Context) error {
			hasRun = true
			return errgo.New("test error")
		},
	}
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	_, err = v1.NewAPIHandler(s.pool, identity.ServerParams{
		AuthUsername:   adminUsername,
		AuthPassword:   adminPassword,
		Key:            key,
		Location:       location,
		MaxMgoSessions: 50,
		PrivateAddr:    "localhost",
		IdentityProviders: []idp.IdentityProvider{
			tidp,
		},
	})
	c.Assert(err, gc.ErrorMatches, "test error")
	c.Assert(hasRun, gc.Equals, true)
}

type testIDP struct {
	c           *gc.C
	name        string
	domain      string
	description string
	interactive bool
	url         func(idp.Context, string) string
	init        func(idp.Context) error
	handle      func(idp.RequestContext, http.ResponseWriter, *http.Request)
}

func (idp *testIDP) Name() string {
	return idp.name
}

func (idp *testIDP) Domain() string {
	return idp.domain
}

func (idp *testIDP) Description() string {
	return idp.description
}

func (idp *testIDP) Interactive() bool {
	return idp.interactive
}

func (idp *testIDP) URL(ctx idp.Context, waitid string) string {
	if idp.url != nil {
		return idp.url(ctx, waitid)
	}
	idp.c.Error("URL called unexpectedly")
	return ""
}

func (idp *testIDP) Init(ctx idp.Context) error {
	if idp.init != nil {
		return idp.init(ctx)
	}
	idp.c.Error("Init called unexpectedly")
	return nil
}

func (idp *testIDP) Handle(c idp.RequestContext, w http.ResponseWriter, req *http.Request) {
	if idp.handle != nil {
		idp.handle(c, w, req)
		return
	}
	idp.c.Error("Handle called unexpectedly")
}
