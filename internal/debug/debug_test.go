// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package debug_test

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/juju/mgotest"
	"github.com/juju/testing"
	"github.com/juju/testing/httptesting"
	"github.com/juju/utils/debugstatus"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/internal/candidtest"
	"github.com/CanonicalLtd/candid/internal/debug"
	"github.com/CanonicalLtd/candid/internal/identity"
	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/mgostore"
	buildver "github.com/CanonicalLtd/candid/version"
)

const (
	version = "debug"
)

type debugSuite struct {
	testing.CleanupSuite
	candidtest.ServerSuite

	db      *mgotest.Database
	backend store.Backend
}

var _ = gc.Suite(&debugSuite{})

func (s *debugSuite) SetUpTest(c *gc.C) {
	s.CleanupSuite.SetUpTest(c)
	var err error
	s.db, err = mgotest.New()
	if errgo.Cause(err) == mgotest.ErrDisabled {
		c.Skip("mgotest disabled")
	}
	c.Assert(err, gc.Equals, nil)
	s.backend, err = mgostore.NewBackend(s.db.Database)
	c.Assert(err, gc.Equals, nil)

	s.Params.MeetingStore = s.backend.MeetingStore()
	s.Params.RootKeyStore = s.backend.BakeryRootKeyStore()
	s.Params.Store = s.backend.Store()
	s.Params.DebugStatusCheckerFuncs = s.backend.DebugStatusCheckerFuncs()
	s.Versions = map[string]identity.NewAPIHandlerFunc{
		version: debug.NewAPIHandler,
	}
	s.ServerSuite.SetUpTest(c)
}

func (s *debugSuite) TearDownTest(c *gc.C) {
	s.ServerSuite.TearDownTest(c)
	if s.backend != nil {
		s.backend.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
	s.CleanupSuite.TearDownTest(c)
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
			c.Assert(err, gc.Equals, nil)
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
