// Copyright 2014 Canonical Ltd.

package router_test

import (
	"errors"
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

func (s *muxSuite) TestAuthorizingHandler(c *gc.C) {
	tests := []struct {
		about        string
		f            func(*http.Request) error
		h            http.Handler
		method       string
		expectStatus int
		expectBody   interface{}
	}{{
		about: "allowed request",
		f: func(_ *http.Request) error {
			return nil
		},
		h: router.HandleJSON(func(_ http.Header, _ *http.Request) (interface{}, error) {
			return "OK", nil
		}),
		expectStatus: http.StatusOK,
		expectBody:   "OK",
	}, {
		about: "forbidden request",
		f: func(_ *http.Request) error {
			return errgo.WithCausef(nil, params.ErrForbidden, "forbidden")
		},
		expectStatus: http.StatusForbidden,
		expectBody:   params.Error{"forbidden", "forbidden"},
	}, {
		about: "allowed GET request",
		f: func(r *http.Request) error {
			if r.Method == "GET" {
				return nil
			}
			return errgo.WithCausef(nil, params.ErrForbidden, "forbidden")
		},
		h: router.HandleJSON(func(_ http.Header, _ *http.Request) (interface{}, error) {
			return "OK", nil
		}),
		expectStatus: http.StatusOK,
		expectBody:   "OK",
	}, {
		about: "forbidden POST request",
		f: func(r *http.Request) error {
			if r.Method == "GET" {
				return nil
			}
			return errgo.WithCausef(nil, params.ErrForbidden, "forbidden")
		},
		method:       "POST",
		expectStatus: http.StatusForbidden,
		expectBody:   params.Error{"forbidden", "forbidden"},
	}, {
		about: "Unauthorized error",
		f: func(r *http.Request) error {
			return errgo.WithCausef(nil, params.ErrUnauthorized, "need auth")
		},
		method:       "POST",
		expectStatus: http.StatusUnauthorized,
		expectBody:   params.Error{"need auth", "unauthorized"},
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		h := router.AuthorizingHandler{
			CheckAuthorized: test.f,
			Handler:         test.h,
		}
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:      h,
			Method:       test.method,
			ExpectStatus: test.expectStatus,
			ExpectBody:   test.expectBody,
		})
	}
}

func (s *muxSuite) TestAnyAccessChecker(c *gc.C) {
	err := errors.New("test error")
	tests := []struct {
		about       string
		f           []func(*http.Request) error
		expectError error
	}{{
		about: "single success",
		f: []func(*http.Request) error{
			func(_ *http.Request) error {
				return nil
			},
		},
		expectError: nil,
	}, {
		about: "single failure",
		f: []func(*http.Request) error{
			func(_ *http.Request) error {
				return err
			},
		},
		expectError: err,
	}, {
		about:       "zero suceeds",
		f:           []func(*http.Request) error{},
		expectError: nil,
	}, {
		about: "many all fail",
		f: []func(*http.Request) error{
			func(_ *http.Request) error {
				return err
			},
			func(_ *http.Request) error {
				return err
			},
		},
		expectError: err,
	}, {
		about: "many one succeeds",
		f: []func(*http.Request) error{
			func(_ *http.Request) error {
				return err
			},
			func(_ *http.Request) error {
				return nil
			},
		},
		expectError: nil,
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		f := router.Any(test.f...)
		obtained := f(nil)
		c.Assert(obtained, gc.Equals, test.expectError)
	}
}

func (s *muxSuite) TestHasMethodAccessChecker(c *gc.C) {
	tests := []struct {
		about       string
		methods     []string
		method      string
		expectCause error
	}{{
		about: "single match",
		methods: []string{
			"GET",
		},
		method:      "GET",
		expectCause: nil,
	}, {
		about: "single non-match",
		methods: []string{
			"GET",
		},
		method:      "POST",
		expectCause: params.ErrBadRequest,
	}, {
		about:       "no methods",
		methods:     []string{},
		method:      "GET",
		expectCause: params.ErrBadRequest,
	}, {
		about: "many with match",
		methods: []string{
			"GET",
			"HEAD",
		},
		method:      "GET",
		expectCause: nil,
	}, {
		about: "many without match",
		methods: []string{
			"GET",
			"HEAD",
		},
		method:      "CONNECT",
		expectCause: params.ErrBadRequest,
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		f := router.HasMethod(test.methods...)
		obtained := f(&http.Request{Method: test.method})
		c.Assert(errgo.Cause(obtained), gc.Equals, test.expectCause)
	}
}
