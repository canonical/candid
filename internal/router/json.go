// Copyright 2014 Canonical Ltd.

package router

import (
	"net/http"

	"github.com/juju/utils/jsonhttp"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/params"
)

var (
	HandleErrors = jsonhttp.HandleErrors(errToResp)
	HandleJSON   = jsonhttp.HandleJSON(errToResp)
	WriteError   = jsonhttp.WriteError(errToResp)
)

func errToResp(err error) (int, interface{}) {
	errorBody := errorResponseBody(err)
	status := http.StatusInternalServerError
	switch errorBody.Code {
	case params.ErrNotFound:
		status = http.StatusNotFound
	case params.ErrForbidden, params.ErrAlreadyExists:
		status = http.StatusForbidden
	case params.ErrBadRequest:
		status = http.StatusBadRequest
	case params.ErrUnauthorized:
		status = http.StatusUnauthorized
	}
	return status, errorBody
}

// errorResponse returns an appropriate error response for the provided error.
func errorResponseBody(err error) *params.Error {
	errResp := &params.Error{
		Message: err.Error(),
	}
	cause := errgo.Cause(err)
	if coder, ok := cause.(errorCoder); ok {
		errResp.Code = coder.ErrorCode()
	}
	return errResp
}

type errorCoder interface {
	ErrorCode() params.ErrorCode
}

// NotFoundHandler is like http.NotFoundHandler except it
// returns a JSON error response.
func NotFoundHandler() http.Handler {
	return HandleErrors(func(w http.ResponseWriter, req *http.Request) error {
		return errgo.WithCausef(nil, params.ErrNotFound, params.ErrNotFound.Error())
	})
}
