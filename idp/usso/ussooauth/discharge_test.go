// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package ussooauth_test

import (
	"github.com/juju/usso"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/juju/idmclient.v1/ussologin"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/mockusso"
	"github.com/CanonicalLtd/blues-identity/idp/usso/ussooauth"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
	"github.com/CanonicalLtd/blues-identity/store"
)

type dischargeSuite struct {
	idmtest.DischargeSuite
	mockusso.Suite
}

var _ = gc.Suite(&dischargeSuite{})

func (s *dischargeSuite) SetUpSuite(c *gc.C) {
	s.Suite.SetUpSuite(c)
	s.DischargeSuite.SetUpSuite(c)
}

func (s *dischargeSuite) TearDownSuite(c *gc.C) {
	s.DischargeSuite.TearDownSuite(c)
	s.Suite.TearDownSuite(c)
}

func (s *dischargeSuite) SetUpTest(c *gc.C) {
	s.Suite.SetUpTest(c)
	s.Params.IdentityProviders = []idp.IdentityProvider{
		ussooauth.IdentityProvider,
	}
	s.DischargeSuite.SetUpTest(c)
}

func (s *dischargeSuite) TearDownTest(c *gc.C) {
	s.DischargeSuite.TearDownTest(c)
	s.Suite.TearDownTest(c)
}

func (s *dischargeSuite) TestDischarge(c *gc.C) {
	err := s.Params.Store.UpdateIdentity(
		s.Ctx,
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("usso", "https://login.ubuntu.com/+id/1234"),
			Username:   "test",
			Name:       "Test User",
			Email:      "test@example.com",
			Groups:     []string{"test"},
		},
		store.Update{
			store.Username: store.Set,
			store.Name:     store.Set,
			store.Email:    store.Set,
			store.Groups:   store.Set,
		},
	)
	c.Assert(err, gc.Equals, nil)
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "1234",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
		Groups: []string{
			"test",
		},
		ConsumerSecret: "secret1",
		TokenKey:       "test-token",
		TokenSecret:    "secret2",
	})
	s.MockUSSO.SetLoginUser("1234")
	interactor := ussologin.NewInteractor(tokenGetterFunc(func(_ context.Context) (*usso.SSOData, error) {
		return &usso.SSOData{
			ConsumerKey:    "1234",
			ConsumerSecret: "secret1",
			TokenKey:       "test-token",
			TokenName:      "test-token",
			TokenSecret:    "secret2",
		}, nil
	}))
	s.AssertDischarge(c, interactor)
}

type tokenGetterFunc func(context.Context) (*usso.SSOData, error)

func (f tokenGetterFunc) GetToken(ctx context.Context) (*usso.SSOData, error) {
	return f(ctx)
}
