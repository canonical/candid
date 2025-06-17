// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package identity_test

import (
	"net/http"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/loggo"
	"github.com/juju/qthttptest"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"

	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/internal/identity"
	"github.com/canonical/candid/params"
)

func TestHandleErrors(t *testing.T) {
	c := qt.New(t)
	for httpErr, paramsErr := range map[int]params.ErrorCode{
		http.StatusNotFound:           params.ErrNotFound,
		http.StatusForbidden:          params.ErrForbidden,
		http.StatusBadRequest:         params.ErrBadRequest,
		http.StatusUnauthorized:       params.ErrUnauthorized,
		http.StatusServiceUnavailable: params.ErrServiceUnavailable,
	} {
		c.Run(string(paramsErr), func(c *qt.C) {
			mux := httprouter.New()
			mux.Handle("GET", "/error/", identity.ReqServer.HandleErrors(func(httprequest.Params) error {
				return errgo.WithCausef(nil, paramsErr, "bad wolf")
			}))
			qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
				Handler:      mux,
				URL:          "/error/",
				ExpectStatus: httpErr,
				ExpectBody: params.Error{
					Message: "bad wolf",
					Code:    paramsErr,
				},
			})
		})
	}
}

func TestHandleErrorsInternalServerError(t *testing.T) {
	c := qt.New(t)
	defer c.Done()
	candidtest.LogTo(c)
	w := new(loggo.TestWriter)
	err := loggo.RegisterWriter("test", w)
	c.Assert(err, qt.IsNil)
	mux := httprouter.New()
	mux.Handle("GET", "/error/", identity.ReqServer.HandleErrors(func(httprequest.Params) error {
		return errgo.New("bad wolf")
	}))
	qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
		Handler:      mux,
		URL:          "/error/",
		ExpectStatus: http.StatusInternalServerError,
		ExpectBody: params.Error{
			Message: "bad wolf",
		},
	})
	assertLogMatches(c, w.Log(), loggo.ERROR, `Internal Server Error: bad wolf \(.*\)`)
}

func TestHandleErrorsSuccess(t *testing.T) {
	c := qt.New(t)
	mux := httprouter.New()
	mux.Handle("GET", "/valid/", identity.ReqServer.HandleErrors(func(httprequest.Params) error {
		return nil
	}))

	// The valid path returns a response without errors.
	qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
		Handler: mux,
		URL:     "/valid/",
	})
}

func TestHandleJSON(t *testing.T) {
	c := qt.New(t)
	// Set up server paths.
	mux := httprouter.New()
	mux.Handle("GET", "/bad-request/", identity.ReqServer.HandleJSON(func(httprequest.Params) (interface{}, error) {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "bad wolf")
	}))
	mux.Handle("GET", "/valid/", identity.ReqServer.HandleJSON(func(httprequest.Params) (interface{}, error) {
		return "success", nil
	}))

	// The bad-request path returns an error response.
	qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
		Handler:      mux,
		URL:          "/bad-request/",
		ExpectStatus: http.StatusBadRequest,
		ExpectBody: params.Error{
			Message: "bad wolf",
			Code:    params.ErrBadRequest,
		},
	})

	// The valid path returns a success response.
	qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
		Handler:    mux,
		URL:        "/valid/",
		ExpectBody: "success",
	})
}
