// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone_test

import (
	qt "github.com/frankban/quicktest"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/idptest"
	keystoneidp "github.com/canonical/candid/idp/keystone"
	"github.com/canonical/candid/idp/keystone/internal/keystone"
	"github.com/canonical/candid/idp/keystone/internal/mockkeystone"
	"github.com/canonical/candid/internal/candidtest"
)

const idpPrefix = "https://idp.example.com"

type fixture struct {
	idptest *idptest.Fixture
	server  *mockkeystone.Server
	params  keystoneidp.Params
	idp     idp.IdentityProvider
}

type fixtureParams struct {
	newIDP func(p keystoneidp.Params) idp.IdentityProvider

	// The folllowing fields correspond with similarly named
	// fields in mockkeystone.Server, which will be initialized
	// with the values there.
	tokensFunc     func(*keystone.TokensRequest) (*keystone.TokensResponse, error)
	authTokensFunc func(*keystone.AuthTokensRequest) (*keystone.AuthTokensResponse, error)
	tenantsFunc    func(*keystone.TenantsRequest) (*keystone.TenantsResponse, error)
	userGroupsFunc func(*keystone.UserGroupsRequest) (*keystone.UserGroupsResponse, error)
}

func newFixture(c *qt.C, p fixtureParams) *fixture {
	s := &fixture{}
	candidtest.LogTo(c)
	s.idptest = idptest.NewFixture(c, candidtest.NewStore())
	s.server = mockkeystone.NewServer()
	c.Defer(s.server.Close)
	s.params = keystoneidp.Params{
		Name:        "openstack",
		Description: "OpenStack",
		Domain:      "openstack",
		URL:         s.server.URL,
	}
	s.server.TokensFunc = p.tokensFunc
	s.server.AuthTokensFunc = p.authTokensFunc
	s.server.TenantsFunc = p.tenantsFunc
	s.server.UserGroupsFunc = p.userGroupsFunc
	s.idp = p.newIDP(s.params)
	err := s.idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, idpPrefix))
	c.Assert(err, qt.IsNil)
	return s
}
