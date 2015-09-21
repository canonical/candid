// Copyright 2015 Canonical Ltd.

package mockkeystone

import (
	"net/http"
	"net/http/httptest"

	"github.com/juju/httprequest"
	"github.com/julienschmidt/httprouter"

	"github.com/CanonicalLtd/blues-identity/internal/keystone"
)

// Server provides a mock keystone server for use in tests.
type Server struct {
	*httptest.Server

	// TokensFunc handles the /v2.0/tokens endpoint. This must be set
	// before the endpoint can be used.
	TokensFunc func(*keystone.TokensRequest) (*keystone.TokensResponse, error)

	// TenantsFunc handles the /v2.0/tenants endpoint. This must be set
	// before the endpoint can be used.
	TenantsFunc func(*keystone.TenantsRequest) (*keystone.TenantsResponse, error)
}

// NewServer creates a new Server for use in tests.
func NewServer() *Server {
	s := new(Server)
	router := httprouter.New()
	for _, h := range errorMapper.Handlers(s.handler) {
		router.Handle(h.Method, h.Path, h.Handle)
	}
	s.Server = httptest.NewServer(router)
	return s
}

// handler creates a new handler for a request.
func (s *Server) handler(httprequest.Params) (*handler, error) {
	return &handler{
		tokens:  s.TokensFunc,
		tenants: s.TenantsFunc,
	}, nil
}

var errorMapper httprequest.ErrorMapper = func(err error) (int, interface{}) {
	var resp keystone.ErrorResponse
	if kerr, ok := err.(*keystone.Error); ok {
		resp.Error = kerr
	} else {
		resp.Error = &keystone.Error{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		}
	}
	return resp.Error.Code, &resp
}

type handler struct {
	tokens  func(*keystone.TokensRequest) (*keystone.TokensResponse, error)
	tenants func(*keystone.TenantsRequest) (*keystone.TenantsResponse, error)
}

func (h *handler) Tokens(r *keystone.TokensRequest) (*keystone.TokensResponse, error) {
	return h.tokens(r)
}

func (h *handler) Tenants(r *keystone.TenantsRequest) (*keystone.TenantsResponse, error) {
	return h.tenants(r)
}
