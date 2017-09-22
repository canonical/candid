// Copyright 2014 Canonical Ltd.

package debug_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"time"

	"github.com/juju/testing"
	"github.com/juju/testing/httptesting"
	"github.com/juju/utils/debugstatus"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/mgo.v2"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/usso"
	"github.com/CanonicalLtd/blues-identity/internal/debug"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	buildver "github.com/CanonicalLtd/blues-identity/version"
)

const (
	version       = "debug"
	adminUsername = "admin"
	adminPassword = "password"
	location      = "https://0.1.2.3/identity"
)

type apiSuite struct {
	testing.IsolatedMgoSuite
	srv     *identity.Server
	pool    *store.Pool
	keyPair *bakery.KeyPair
	teams   []string
	server  *httptest.Server
}

func (s *apiSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)

	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.srv, s.pool = newServer(c, s.Session, key, s.teams)
	s.keyPair = key
	s.server = httptest.NewServer(s.srv)
	s.PatchValue(&http.DefaultTransport, httptesting.URLRewritingTransport{
		MatchPrefix:  location,
		Replace:      s.server.URL,
		RoundTripper: http.DefaultTransport,
	})
}

func (s *apiSuite) TearDownTest(c *gc.C) {
	s.srv.Close()
	s.pool.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

func newServer(c *gc.C, session *mgo.Session, key *bakery.KeyPair, teams []string) (*identity.Server, *store.Pool) {
	db := session.DB("testing")
	sp := identity.ServerParams{
		AuthUsername:   adminUsername,
		AuthPassword:   adminPassword,
		Key:            key,
		Location:       location,
		MaxMgoSessions: 50,
		PrivateAddr:    "localhost",
		IdentityProviders: []idp.IdentityProvider{
			usso.IdentityProvider,
		},
		DebugTeams: teams,
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
	srv, err := identity.New(
		db,
		sp,
		map[string]identity.NewAPIHandlerFunc{
			version: debug.NewAPIHandler,
		},
	)
	c.Assert(err, gc.IsNil)
	return srv, pool
}

type debugSuite struct {
	apiSuite
}

var _ = gc.Suite(&debugSuite{})

func (s *debugSuite) patchStartTime() time.Time {
	startTime := time.Now()
	s.PatchValue(&debugstatus.StartTime, startTime)
	return startTime
}

func (s *debugSuite) TestServeDebugStatus(c *gc.C) {
	startTime := s.patchStartTime()
	expectNames := map[string]string{
		"server_started":    "Server started",
		"mongo_connected":   "MongoDB is connected",
		"mongo_collections": "MongoDB collections",
		"meeting_count":     "count of meeting collection",
		"nonce_count":       "count of usso nonces collection",
	}
	expectValues := map[string]string{
		"server_started":    regexp.QuoteMeta(startTime.String()),
		"mongo_connected":   "Connected",
		"mongo_collections": "All required collections exist",
		"meeting_count":     "0",
		"store_pool_status": "free: [01]; limit: 50; size: [12]",
		"nonce_count":       "0",
	}
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     "/debug/status",
		ExpectBody: httptesting.BodyAsserter(func(c *gc.C, body json.RawMessage) {
			var result map[string]debugstatus.CheckResult
			err := json.Unmarshal(body, &result)
			c.Assert(err, gc.IsNil)
			c.Assert(result, gc.HasLen, len(expectNames))
			for k, v := range result {
				c.Assert(v.Name, gc.Equals, expectNames[k], gc.Commentf("%s: incorrect name", k))
				c.Assert(v.Value, gc.Matches, expectValues[k], gc.Commentf("%s: incorrect value", k))
			}
		}),
	})
}

func (s *debugSuite) TestServeDebugInfo(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      s.srv,
		URL:          "/debug/info",
		ExpectStatus: http.StatusOK,
		ExpectBody:   buildver.VersionInfo,
	})
}
