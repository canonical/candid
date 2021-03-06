// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	envschemaform "gopkg.in/juju/environschema.v1/form"
	"gopkg.in/macaroon-bakery.v3/httpbakery"
	"gopkg.in/macaroon-bakery.v3/httpbakery/form"

	"github.com/canonical/candid/v2/idp"
	"github.com/canonical/candid/v2/idp/keystone"
	"github.com/canonical/candid/v2/idp/keystone/internal/mockkeystone"
	"github.com/canonical/candid/v2/internal/candidtest"
	"github.com/canonical/candid/v2/internal/discharger"
	"github.com/canonical/candid/v2/internal/identity"
)

type dischargeSuite struct {
	candid           *candidtest.Server
	dischargeCreator *candidtest.DischargeCreator
	server           *mockkeystone.Server
	params           keystone.Params
}

func TestDischarge(t *testing.T) {
	qtsuite.Run(qt.New(t), &dischargeSuite{})
}

func (s *dischargeSuite) Init(c *qt.C) {
	candidtest.LogTo(c)

	s.server = mockkeystone.NewServer()
	c.Defer(s.server.Close)
	s.params = keystone.Params{
		Name:        "openstack",
		Description: "OpenStack",
		Domain:      "openstack",
		URL:         s.server.URL,
	}
	s.server.TokensFunc = testTokens
	s.server.TenantsFunc = testTenants

	store := candidtest.NewStore()
	sp := store.ServerParams()
	sp.IdentityProviders = []idp.IdentityProvider{
		keystone.NewIdentityProvider(s.params),
		keystone.NewUserpassIdentityProvider(
			keystone.Params{
				Name:        "form",
				Domain:      s.params.Domain,
				Description: s.params.Description,
				URL:         s.params.URL,
			},
		),
		keystone.NewTokenIdentityProvider(
			keystone.Params{
				Name:        "token",
				Domain:      s.params.Domain,
				Description: s.params.Description,
				URL:         s.params.URL,
			},
		),
	}
	s.candid = candidtest.NewServer(c, sp, map[string]identity.NewAPIHandlerFunc{
		"discharger": discharger.NewAPIHandler,
	})
	s.dischargeCreator = candidtest.NewDischargeCreator(s.candid)

}

func (s *dischargeSuite) TestInteractiveDischarge(c *qt.C) {
	s.dischargeCreator.AssertDischarge(c, httpbakery.WebBrowserInteractor{
		OpenWebBrowser: candidtest.PasswordLogin(c, "testuser", "testpass"),
	})
}

func (s *dischargeSuite) TestFormDischarge(c *qt.C) {
	s.dischargeCreator.AssertDischarge(c, form.Interactor{
		Filler: keystoneFormFiller{
			username: "testuser",
			password: "testpass",
		},
	})
}

type keystoneFormFiller struct {
	username, password string
}

func (h keystoneFormFiller) Fill(f envschemaform.Form) (map[string]interface{}, error) {
	if _, ok := f.Fields["username"]; !ok {
		return nil, errgo.New("schema has no username")
	}
	if _, ok := f.Fields["password"]; !ok {
		return nil, errgo.New("schema has no password")
	}
	return map[string]interface{}{
		"username": h.username,
		"password": h.password,
	}, nil
}

func (s *dischargeSuite) TestTokenDischarge(c *qt.C) {
	s.dischargeCreator.AssertDischarge(c, &tokenInteractor{})
}

type tokenLoginRequest struct {
	httprequest.Route `httprequest:"POST"`
	Token             keystone.Token `httprequest:",body"`
}

type TokenInteractionInfo struct {
	URL string `json:"url"`
}

type tokenInteractor struct{}

func (i *tokenInteractor) Kind() string {
	return "token"
}

func (i *tokenInteractor) Interact(ctx context.Context, client *httpbakery.Client, location string, ierr *httpbakery.Error) (*httpbakery.DischargeToken, error) {
	var info keystone.TokenInteractionInfo
	if err := ierr.InteractionMethod("token", &info); err != nil {
		return nil, errgo.Mask(err, errgo.Is(httpbakery.ErrInteractionMethodNotFound))
	}
	var req keystone.TokenLoginRequest
	req.Token.Login.ID = "789"
	var resp keystone.TokenLoginResponse
	cl := &httprequest.Client{
		Doer: client,
	}
	if err := cl.CallURL(ctx, info.URL, &req, &resp); err != nil {
		return nil, errgo.Mask(err)
	}
	return resp.DischargeToken, nil
}
