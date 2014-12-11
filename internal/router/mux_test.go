// Copyright 2014 Canonical Ltd.

package router_test

import (
	"net/http"

	jujutesting "github.com/juju/testing"
	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/router"
	"github.com/CanonicalLtd/blues-identity/params"
)

type muxSuite struct {
	jujutesting.IsolationSuite
}

var _ = gc.Suite(&muxSuite{})

func exampleHandler(http.Header, *http.Request) (interface{}, error) {
	return "example", nil
}

func (s *muxSuite) TestNewServeMux(c *gc.C) {
	// Set up a mux with a single handler.
	mux := router.NewServeMux()
	mux.Handle("/path/", router.HandleJSON(exampleHandler))

	// Requests to the handler path are handled correctly.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:    mux,
		URL:        "/path/",
		ExpectBody: "example",
	})

	// Requests to other pages return a JSON not found response.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      mux,
		URL:          "/no-such/",
		ExpectStatus: http.StatusNotFound,
		ExpectBody: params.Error{
			Message: `no handler for "/no-such/"`,
			Code:    params.ErrNotFound,
		},
	})
}
