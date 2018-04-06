// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mockkeystone

import (
	"net/http"
	"net/http/httptest"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/context"
	"gopkg.in/httprequest.v1"

	"github.com/CanonicalLtd/candid/idp/keystone/internal/keystone"
)

// Server provides a mock keystone server for use in tests.
type Server struct {
	*httptest.Server

	// TokensFunc handles the /v2.0/tokens endpoint. This must be set
	// before the endpoint can be used.
	TokensFunc func(*keystone.TokensRequest) (*keystone.TokensResponse, error)

	// AuthTokensFunc handles the /v3/auth/tokens endpoint. This must
	// be set before the endpoint can be used.
	AuthTokensFunc func(*keystone.AuthTokensRequest) (*keystone.AuthTokensResponse, error)

	// TenantsFunc handles the /v2.0/tenants endpoint. This must be set
	// before the endpoint can be used.
	TenantsFunc func(*keystone.TenantsRequest) (*keystone.TenantsResponse, error)

	// UserGroupsFunc handles the /v3/users/:id/groups endpoint. This must be set
	// before the endpoint can be used.
	UserGroupsFunc func(*keystone.UserGroupsRequest) (*keystone.UserGroupsResponse, error)
}

// NewServer creates a new Server for use in tests.
func NewServer() *Server {
	s := new(Server)
	router := httprouter.New()
	for _, h := range reqServer.Handlers(s.handler) {
		router.Handle(h.Method, h.Path, h.Handle)
	}
	s.Server = httptest.NewServer(router)
	return s
}

// handler creates a new handler for a request.
func (s *Server) handler(p httprequest.Params) (*handler, context.Context, error) {
	return &handler{
		tokens:     s.TokensFunc,
		authTokens: s.AuthTokensFunc,
		tenants:    s.TenantsFunc,
		userGroups: s.UserGroupsFunc,
	}, p.Context, nil
}

var reqServer = httprequest.Server{
	ErrorMapper: func(ctx context.Context, err error) (int, interface{}) {
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
	},
}

type handler struct {
	tokens     func(*keystone.TokensRequest) (*keystone.TokensResponse, error)
	authTokens func(*keystone.AuthTokensRequest) (*keystone.AuthTokensResponse, error)
	tenants    func(*keystone.TenantsRequest) (*keystone.TenantsResponse, error)
	userGroups func(*keystone.UserGroupsRequest) (*keystone.UserGroupsResponse, error)
}

func (h *handler) Tokens(r *keystone.TokensRequest) (*keystone.TokensResponse, error) {
	return h.tokens(r)
}

func (h *handler) AuthTokens(r *keystone.AuthTokensRequest) (*keystone.AuthTokensResponse, error) {
	return h.authTokens(r)
}

func (h *handler) Tenants(r *keystone.TenantsRequest) (*keystone.TenantsResponse, error) {
	return h.tenants(r)
}

func (h *handler) UserGroups(r *keystone.UserGroupsRequest) (*keystone.UserGroupsResponse, error) {
	return h.userGroups(r)
}
