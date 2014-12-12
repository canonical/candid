// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"encoding/json"
	"net/http"

	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"

	"github.com/juju/utils/debugstatus"
)

type debugSuite struct {
	apiSuite
}

var _ = gc.Suite(&debugSuite{})

func (s *debugSuite) TestServeDebugStatus(c *gc.C) {
	rec := httptesting.DoRequest(c, httptesting.DoRequestParams{
		Handler: s.srv,
		URL:     apiURL("debug/status"),
	})
	c.Assert(rec.Code, gc.Equals, http.StatusOK, gc.Commentf("body: %s", rec.Body.Bytes()))
	c.Assert(rec.Header().Get("Content-Type"), gc.Equals, "application/json")

	// Ensure the results are properly returned.
	var results map[string]debugstatus.CheckResult
	err := json.Unmarshal(rec.Body.Bytes(), &results)
	c.Assert(err, gc.IsNil)
	c.Assert(results, gc.HasLen, 3)
	c.Assert(results["mongo_connected"], jc.DeepEquals, debugstatus.CheckResult{
		Name:   "MongoDB is connected",
		Value:  "Connected",
		Passed: true,
	})
	c.Assert(results["mongo_collections"], jc.DeepEquals, debugstatus.CheckResult{
		Name:   "MongoDB collections",
		Value:  "All required collections exist",
		Passed: true,
	})
	c.Assert(results["server_started"].Passed, jc.IsTrue)
}
