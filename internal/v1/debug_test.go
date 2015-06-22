// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"encoding/json"
	"net/http"
	"time"

	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	"github.com/juju/utils/debugstatus"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/params"
	buildver "github.com/CanonicalLtd/blues-identity/version"
)

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
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("debug/status"),
		ExpectBody: httptesting.BodyAsserter(func(c *gc.C, body json.RawMessage) {
			var result map[string]debugstatus.CheckResult
			err := json.Unmarshal(body, &result)
			c.Assert(err, gc.IsNil)
			for k, v := range result {
				v.Duration = 0
				result[k] = v
			}
			c.Assert(result, jc.DeepEquals, map[string]debugstatus.CheckResult{
				"server_started": {
					Name:   "Server started",
					Value:  startTime.String(),
					Passed: true,
				},
				"mongo_connected": {
					Name:   "MongoDB is connected",
					Value:  "Connected",
					Passed: true,
				},
				"mongo_collections": {
					Name:   "MongoDB collections",
					Value:  "All required collections exist",
					Passed: true,
				},
			})
		}),
	})
}

func (s *debugSuite) TestServeDebugInfo(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      s.srv,
		URL:          apiURL("debug/info"),
		ExpectStatus: http.StatusOK,
		ExpectBody:   buildver.VersionInfo,
	})
}

func (s *debugSuite) TestServeDebug(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      s.srv,
		URL:          apiURL("debug"),
		ExpectStatus: http.StatusInternalServerError,
		ExpectBody: params.Error{
			Message: "method not implemented",
		},
	})
}

var debugPprofTests = []struct {
	about        string
	url          string
	username     string
	password     string
	expectStatus int
	expectBody   interface{}
}{{
	about:        "get debug/pprof/",
	url:          apiURL("debug/pprof/"),
	username:     adminUsername,
	password:     adminPassword,
	expectStatus: http.StatusOK,
}, {
	about:        "get debug/pprof/ invalid username",
	url:          apiURL("debug/pprof/"),
	username:     adminUsername + "bad",
	password:     adminPassword,
	expectStatus: http.StatusUnauthorized,
	expectBody: params.Error{
		Code:    params.ErrUnauthorized,
		Message: "invalid credentials",
	},
}, {
	about:        "get debug/pprof/ no credentials",
	url:          apiURL("debug/pprof/"),
	expectStatus: http.StatusProxyAuthRequired,
	expectBody:   DischargeRequiredBody,
}, {
	about:        "get debug/pprof/cmdline",
	url:          apiURL("debug/pprof/cmdline"),
	username:     adminUsername,
	password:     adminPassword,
	expectStatus: http.StatusOK,
}, {
	about:        "get debug/pprof/profile",
	url:          apiURL("debug/pprof/profile"),
	username:     adminUsername,
	password:     adminPassword,
	expectStatus: http.StatusOK,
}, {
	about:        "get debug/pprof/symbol",
	url:          apiURL("debug/pprof/symbol"),
	username:     adminUsername,
	password:     adminPassword,
	expectStatus: http.StatusOK,
}, {
	about:        "get debug/pprof/goroutine",
	url:          apiURL("debug/pprof/goroutine"),
	username:     adminUsername,
	password:     adminPassword,
	expectStatus: http.StatusOK,
}, {
	about:        "get debug/pprof/cmdline bad credentials",
	url:          apiURL("debug/pprof/cmdline"),
	username:     adminUsername + "bad",
	password:     adminPassword,
	expectStatus: http.StatusUnauthorized,
	expectBody: params.Error{
		Code:    params.ErrUnauthorized,
		Message: "invalid credentials",
	},
}, {
	about:        "get debug/pprof/cmdline no credentials",
	url:          apiURL("debug/pprof/cmdline"),
	expectStatus: http.StatusProxyAuthRequired,
	expectBody:   DischargeRequiredBody,
}}

func (s *debugSuite) TestServeDebugPprof(c *gc.C) {
	for i, test := range debugPprofTests {
		c.Logf("%d. %s", i, test.about)
		if test.expectBody != nil {
			httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
				Handler:      s.srv,
				URL:          test.url,
				Username:     test.username,
				Password:     test.password,
				ExpectStatus: test.expectStatus,
				ExpectBody:   test.expectBody,
			})
			continue
		}
		rr := httptesting.DoRequest(c, httptesting.DoRequestParams{
			Handler:  s.srv,
			URL:      test.url,
			Username: test.username,
			Password: test.password,
		})
		c.Assert(rr.Code, gc.Equals, test.expectStatus)
	}
}
