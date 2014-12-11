// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"net/http"

	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/params"
)

type debugSuite struct {
	apiSuite
}

var _ = gc.Suite(&debugSuite{})

func (s *debugSuite) TestServeDebugStatus(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      s.srv,
		URL:          apiURL("debug/status"),
		ExpectStatus: http.StatusInternalServerError,
		ExpectBody: params.Error{
			Message: "method not implemented",
		},
	})
}
