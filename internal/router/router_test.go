// Copyright 2014 Canonical Ltd.

package router_test

import (
	"net/http"

	jujutesting "github.com/juju/testing"
	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/internal/router"
	"github.com/CanonicalLtd/blues-identity/params"
)

type routersSuite struct {
	jujutesting.IsolationSuite
}

var _ = gc.Suite(&routersSuite{})

func makeHandler(output string, err error) http.Handler {
	return router.HandleJSON(func(http.Header, *http.Request) (interface{}, error) {
		return output, err
	})
}

var newTests = []struct {
	about        string
	path         string
	expectStatus int
	expectBody   interface{}
}{{
	about:      "successful response",
	path:       "/path",
	expectBody: "success",
}, {
	about:        "error response",
	path:         "/path/to/error",
	expectStatus: http.StatusInternalServerError,
	expectBody: params.Error{
		Message: "path/to/error",
	},
}, {
	about:        "not found",
	path:         "/no-such",
	expectStatus: http.StatusNotFound,
	expectBody: params.Error{
		Message: `no handler for "/no-such"`,
		Code:    params.ErrNotFound,
	},
}, {
	about:      "another successful response",
	path:       "/another-path",
	expectBody: "another success",
}, {
	about:        "forbidden",
	path:         "/forbidden",
	expectStatus: http.StatusForbidden,
	expectBody: params.Error{
		Message: "access denied",
		Code:    params.ErrForbidden,
	},
}}

func (s *muxSuite) TestNew(c *gc.C) {
	// Create a router with some handlers.
	handler := router.New(map[string]http.Handler{
		"path":          makeHandler("success", nil),
		"path/to/error": makeHandler("", errgo.New("path/to/error")),
		"another-path/": makeHandler("another success", nil),
		"forbidden":     makeHandler("", errgo.WithCausef(nil, params.ErrForbidden, "access denied")),
	})

	// Run the tests using the handler.
	for i, test := range newTests {
		c.Logf("test %d: %s", i, test.about)
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:      handler,
			URL:          test.path,
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectBody,
		})
	}
}
