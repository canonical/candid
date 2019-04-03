// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package usso_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/usso"
	"github.com/CanonicalLtd/candid/idp/usso/internal/mockusso"
	"github.com/CanonicalLtd/candid/internal/candidtest"
	"github.com/CanonicalLtd/candid/internal/discharger"
	"github.com/CanonicalLtd/candid/internal/identity"
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
