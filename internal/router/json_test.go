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

type jsonSuite struct {
	jujutesting.IsolationSuite
	mux *http.ServeMux
}

var _ = gc.Suite(&jsonSuite{})

func (s *jsonSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	s.mux = http.NewServeMux()
}

func (s *jsonSuite) TestHandleErrors(c *gc.C) {
	// Set up server paths.
	s.mux.Handle("/forbidden/", router.HandleErrors(func(http.ResponseWriter, *http.Request) error {
		return errgo.WithCausef(nil, params.ErrForbidden, "bad wolf")
	}))
	s.mux.Handle("/valid/", router.HandleErrors(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))

	// The forbidden path returns an error response.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      s.mux,
		URL:          "/forbidden/",
		ExpectStatus: http.StatusForbidden,
		ExpectBody: params.Error{
			Message: "bad wolf",
			Code:    params.ErrForbidden,
		},
	})

	// The valid path returns a response without errors.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.mux,
		URL:     "/valid/",
	})
}

func (s *jsonSuite) TestHandleJSON(c *gc.C) {
	// Set up server paths.
	s.mux.Handle("/bad-request/", router.HandleJSON(func(http.Header, *http.Request) (interface{}, error) {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "bad wolf")
	}))
	s.mux.Handle("/valid/", router.HandleJSON(func(http.Header, *http.Request) (interface{}, error) {
		return "success", nil
	}))

	// The bad-request path returns an error response.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      s.mux,
		URL:          "/bad-request/",
		ExpectStatus: http.StatusBadRequest,
		ExpectBody: params.Error{
			Message: "bad wolf",
			Code:    params.ErrBadRequest,
		},
	})

	// The valid path returns a success response.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:    s.mux,
		URL:        "/valid/",
		ExpectBody: "success",
	})
}

func (s *jsonSuite) TestNotFoundHandler(c *gc.C) {
	s.mux.Handle("/no-such/", router.NotFoundHandler())
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      s.mux,
		URL:          "/no-such/",
		ExpectStatus: http.StatusNotFound,
		ExpectBody: params.Error{
			Message: params.ErrNotFound.Error(),
			Code:    params.ErrNotFound,
		},
	})
}
