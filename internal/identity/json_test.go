// Copyright 2014 Canonical Ltd.

package identity_test

import (
	"net/http"

	"github.com/juju/httprequest"
	jujutesting "github.com/juju/testing"
	"github.com/juju/testing/httptesting"
	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/params"
)

type jsonSuite struct {
	jujutesting.IsolationSuite
	mux *httprouter.Router
}

var _ = gc.Suite(&jsonSuite{})

func (s *jsonSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	s.mux = httprouter.New()
}

func (s *jsonSuite) TestHandleErrors(c *gc.C) {
	for httpErr, paramsErr := range map[int]params.ErrorCode{
		http.StatusNotFound:           params.ErrNotFound,
		http.StatusForbidden:          params.ErrForbidden,
		http.StatusBadRequest:         params.ErrBadRequest,
		http.StatusUnauthorized:       params.ErrUnauthorized,
		http.StatusServiceUnavailable: params.ErrServiceUnavailable,
	} {
		mux := httprouter.New()
		mux.Handle("GET", "/error/", identity.ErrorMapper.HandleErrors(func(httprequest.Params) error {
			return errgo.WithCausef(nil, paramsErr, "bad wolf")
		}))
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:      mux,
			URL:          "/error/",
			ExpectStatus: httpErr,
			ExpectBody: params.Error{
				Message: "bad wolf",
				Code:    paramsErr,
			},
		})
	}
}

func (s *jsonSuite) TestHandleErrorsInternalServerError(c *gc.C) {
	s.mux.Handle("GET", "/error/", identity.ErrorMapper.HandleErrors(func(httprequest.Params) error {
		return errgo.New("bad wolf")
	}))
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      s.mux,
		URL:          "/error/",
		ExpectStatus: http.StatusInternalServerError,
		ExpectBody: params.Error{
			Message: "bad wolf",
		},
	})
}

func (s *jsonSuite) TestHandleErrorsSuccess(c *gc.C) {
	s.mux.Handle("GET", "/valid/", identity.ErrorMapper.HandleErrors(func(httprequest.Params) error {
		return nil
	}))

	// The valid path returns a response without errors.
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.mux,
		URL:     "/valid/",
	})
}

func (s *jsonSuite) TestHandleJSON(c *gc.C) {
	// Set up server paths.
	s.mux.Handle("GET", "/bad-request/", identity.ErrorMapper.HandleJSON(func(httprequest.Params) (interface{}, error) {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "bad wolf")
	}))
	s.mux.Handle("GET", "/valid/", identity.ErrorMapper.HandleJSON(func(httprequest.Params) (interface{}, error) {
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
