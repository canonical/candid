// Copyright 2014 Canonical Ltd.

package debug_test

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/juju/testing"
	"github.com/juju/testing/httptesting"
	"github.com/juju/utils/debugstatus"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2/bakery/mgorootkeystore"

	"github.com/CanonicalLtd/blues-identity/internal/debug"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
	"github.com/CanonicalLtd/blues-identity/mgostore"
	buildver "github.com/CanonicalLtd/blues-identity/version"
)

const (
	version = "debug"
)

type debugSuite struct {
	testing.IsolatedMgoSuite
	idmtest.ServerSuite

	db *mgostore.Database
}

var _ = gc.Suite(&debugSuite{})

func (s *debugSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.db, err = mgostore.NewDatabase(s.Session.DB("idm-test"))
	c.Assert(err, gc.Equals, nil)

	s.Params.MeetingStore = s.db.MeetingStore()
	s.Params.RootKeyStore = s.db.BakeryRootKeyStore(mgorootkeystore.Policy{ExpiryDuration: time.Minute})
	s.Params.Store = s.db.Store()
	s.Params.DebugStatusCheckerFuncs = s.db.DebugStatusCheckerFuncs()
	s.Versions = map[string]identity.NewAPIHandlerFunc{
		version: debug.NewAPIHandler,
	}
	s.ServerSuite.SetUpTest(c)
}

func (s *debugSuite) TearDownTest(c *gc.C) {
	s.ServerSuite.TearDownTest(c)
	s.db.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

func (s *debugSuite) patchStartTime() time.Time {
	startTime := time.Now()
	s.PatchValue(&debugstatus.StartTime, startTime)
	return startTime
}

func (s *debugSuite) TestServeDebugStatus(c *gc.C) {
	startTime := s.patchStartTime()
	expectNames := map[string]string{
		"server_started":    "Server started",
		"mongo_collections": "MongoDB collections",
		"meeting_count":     "count of meeting collection",
	}
	expectValues := map[string]string{
		"server_started":    regexp.QuoteMeta(startTime.String()),
		"mongo_collections": "All required collections exist",
		"meeting_count":     "0",
	}
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		URL: s.URL + "/debug/status",
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
		URL:          s.URL + "/debug/info",
		ExpectStatus: http.StatusOK,
		ExpectBody:   buildver.VersionInfo,
	})
}
