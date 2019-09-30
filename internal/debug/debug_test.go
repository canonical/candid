// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package debug_test

import (
	"encoding/json"
	"net/http"
	"regexp"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/juju/mgotest"
	"github.com/juju/qthttptest"
	"github.com/juju/utils/debugstatus"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/internal/candidtest"
	"github.com/CanonicalLtd/candid/internal/debug"
	"github.com/CanonicalLtd/candid/internal/identity"
	"github.com/CanonicalLtd/candid/store/mgostore"
	buildver "github.com/CanonicalLtd/candid/version"
)

const (
	version = "debug"
)

func TestDebug(t *testing.T) {
	qtsuite.Run(qt.New(t), &debugSuite{})
}

type debugSuite struct {
	srv *candidtest.Server
}

func (s *debugSuite) Init(c *qt.C) {
	s.srv = newFixture(c).srv
}

func (s *debugSuite) patchStartTime(c *qt.C) time.Time {
	startTime := time.Now()
	c.Patch(&debugstatus.StartTime, startTime)
	return startTime
}

func (s *debugSuite) TestServeDebugStatus(c *qt.C) {
	startTime := s.patchStartTime(c)
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
	qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
		URL: s.srv.URL + "/debug/status",
		ExpectBody: qthttptest.BodyAsserter(func(c *qt.C, body json.RawMessage) {
			var result map[string]debugstatus.CheckResult
			err := json.Unmarshal(body, &result)
			c.Assert(err, qt.Equals, nil)
			c.Assert(result, qt.HasLen, len(expectNames))
			for k, v := range result {
				c.Assert(v.Name, qt.Equals, expectNames[k], qt.Commentf("%s: incorrect name", k))
				c.Assert(v.Value, qt.Matches, expectValues[k], qt.Commentf("%s: incorrect value", k))
			}
		}),
	})
}

func (s *debugSuite) TestServeDebugInfo(c *qt.C) {
	qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
		URL:          s.srv.URL + "/debug/info",
		ExpectStatus: http.StatusOK,
		ExpectBody:   buildver.VersionInfo,
	})
}

type fixture struct {
	srv *candidtest.Server
}

func newFixture(c *qt.C) *fixture {
	db, err := mgotest.New()
	if errgo.Cause(err) == mgotest.ErrDisabled {
		c.Skip("mgotest disabled")
	}
	c.Assert(err, qt.Equals, nil)
	// mgotest sets the SocketTimout to 1s. Restore it back to the
	// default value.
	db.Session.SetSocketTimeout(time.Minute)
	backend, err := mgostore.NewBackend(db.Database)
	if err != nil {
		db.Close()
		c.Fatal(err)
	}
	c.Assert(err, qt.Equals, nil)
	c.Defer(backend.Close)

	sp := identity.ServerParams{
		MeetingStore:            backend.MeetingStore(),
		RootKeyStore:            backend.BakeryRootKeyStore(),
		Store:                   backend.Store(),
		DebugStatusCheckerFuncs: backend.DebugStatusCheckerFuncs(),
		DebugTeams:              []string{"debuggers"},
	}
	srv := candidtest.NewServer(c, sp, map[string]identity.NewAPIHandlerFunc{
		version: debug.NewAPIHandler,
	})
	return &fixture{
		srv: srv,
	}
}
