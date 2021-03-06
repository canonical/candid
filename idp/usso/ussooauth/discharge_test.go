// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package ussooauth_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/usso"

	"github.com/canonical/candid/v2/candidclient/ussologin"
	"github.com/canonical/candid/v2/idp"
	"github.com/canonical/candid/v2/idp/usso/internal/mockusso"
	"github.com/canonical/candid/v2/idp/usso/ussooauth"
	"github.com/canonical/candid/v2/internal/candidtest"
	"github.com/canonical/candid/v2/internal/discharger"
	"github.com/canonical/candid/v2/internal/identity"
	"github.com/canonical/candid/v2/store"
)

func TestDischarge(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	testStore := candidtest.NewStore()
	sp := testStore.ServerParams()
	sp.IdentityProviders = []idp.IdentityProvider{
		ussooauth.IdentityProvider,
	}
	candid := candidtest.NewServer(c, sp, map[string]identity.NewAPIHandlerFunc{
		"discharger": discharger.NewAPIHandler,
	})
	dischargeCreator := candidtest.NewDischargeCreator(candid)

	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()

	err := testStore.Store.UpdateIdentity(
		candid.Ctx,
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
	c.Assert(err, qt.IsNil)
	ussoSrv.MockUSSO.AddUser(&mockusso.User{
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
	ussoSrv.MockUSSO.SetLoginUser("1234")
	interactor := ussologin.NewInteractor(tokenGetterFunc(func(_ context.Context) (*usso.SSOData, error) {
		return &usso.SSOData{
			ConsumerKey:    "1234",
			ConsumerSecret: "secret1",
			TokenKey:       "test-token",
			TokenName:      "test-token",
			TokenSecret:    "secret2",
		}, nil
	}))
	dischargeCreator.AssertDischarge(c, interactor)
}

type tokenGetterFunc func(context.Context) (*usso.SSOData, error)

func (f tokenGetterFunc) GetToken(ctx context.Context) (*usso.SSOData, error) {
	return f(ctx)
}
