// Copyright 2019 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package ldap_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"gopkg.in/canonical/candid.v2/idp"
	"gopkg.in/canonical/candid.v2/idp/ldap"
	"gopkg.in/canonical/candid.v2/internal/candidtest"
	"gopkg.in/canonical/candid.v2/internal/discharger"
	"gopkg.in/canonical/candid.v2/internal/identity"
)

func TestInteractiveDischarge(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	store := candidtest.NewStore()
	sp := store.ServerParams()
	ldapIDP, err := ldap.NewIdentityProvider(getSampleParams())
	c.Assert(err, qt.IsNil)
	ldap.SetLDAP(ldapIDP, newMockLDAPDialer(getSampleLdapDB()).Dial)
	sp.IdentityProviders = []idp.IdentityProvider{
		ldapIDP,
	}
	candid := candidtest.NewServer(c, sp, map[string]identity.NewAPIHandlerFunc{
		"discharger": discharger.NewAPIHandler,
	})
	dischargeCreator := candidtest.NewDischargeCreator(candid)
	dischargeCreator.AssertDischarge(c, httpbakery.WebBrowserInteractor{
		OpenWebBrowser: candidtest.PasswordLogin(c, "user1", "pass1"),
	})
}
