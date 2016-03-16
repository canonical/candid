// Copyright 2014 Canonical Ltd.

package identity

import (
	"net/http"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
)

var (
	ErrorMapper = httprequest.ErrorMapper(errToResp)
	WriteError  = ErrorMapper.WriteError
)

func errToResp(err error) (int, interface{}) {
	// Allow bakery errors to be returned as the bakery would
	// like them, so that httpbakery.Client.Do will work.
	if err, ok := errgo.Cause(err).(*httpbakery.Error); ok {
		return httpbakery.ErrorToResponse(err)
	}
	errorBody := errorResponseBody(err)
	status := http.StatusInternalServerError
	switch errorBody.Code {
	case params.ErrNotFound:
		status = http.StatusNotFound
	case params.ErrForbidden, params.ErrAlreadyExists:
		status = http.StatusForbidden
	case params.ErrBadRequest:
		status = http.StatusBadRequest
	case params.ErrUnauthorized, params.ErrNoAdminCredsProvided:
		status = http.StatusUnauthorized
	case params.ErrMethodNotAllowed:
		status = http.StatusMethodNotAllowed
	case params.ErrServiceUnavailable:
		status = http.StatusServiceUnavailable
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
	} else if errgo.Cause(err) == httprequest.ErrUnmarshal {
		errResp.Code = params.ErrBadRequest
	}
	return errResp
}

type errorCoder interface {
	ErrorCode() params.ErrorCode
}
