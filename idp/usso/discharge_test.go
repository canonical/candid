// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package usso_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"gopkg.in/canonical/candid.v2/idp"
	"gopkg.in/canonical/candid.v2/idp/usso"
	"gopkg.in/canonical/candid.v2/idp/usso/internal/mockusso"
	"gopkg.in/canonical/candid.v2/internal/candidtest"
	"gopkg.in/canonical/candid.v2/internal/discharger"
	"gopkg.in/canonical/candid.v2/internal/identity"
)

func TestInteractiveDischarge(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	store := candidtest.NewStore()
	sp := store.ServerParams()
	sp.IdentityProviders = []idp.IdentityProvider{
		usso.NewIdentityProvider(usso.Params{}),
	}
	candid := candidtest.NewServer(c, sp, map[string]identity.NewAPIHandlerFunc{
		"discharger": discharger.NewAPIHandler,
	})
	dischargeCreator := candidtest.NewDischargeCreator(candid)

	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()

	ussoSrv.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
		Groups:   []string{"test1", "test2"},
	})
	ussoSrv.MockUSSO.SetLoginUser("test")
	dischargeCreator.AssertDischarge(c, httpbakery.WebBrowserInteractor{
		OpenWebBrowser: candidtest.OpenWebBrowser(c, candidtest.SelectInteractiveLogin(nil)),
	})
}
