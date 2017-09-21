// Copyright 2015 Canonical Ltd.

package usso_test

import (
	"net/http"
	"net/url"

	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/usso"
	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/mockusso"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
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
		usso.IdentityProvider,
	}
	s.DischargeSuite.SetUpTest(c)
}

func (s *dischargeSuite) TearDownTest(c *gc.C) {
	s.DischargeSuite.TearDownTest(c)
	s.Suite.TearDownTest(c)
}

func (s *dischargeSuite) TestInteractiveDischarge(c *gc.C) {
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
		Groups:   []string{"test1", "test2"},
	})
	s.MockUSSO.SetLoginUser("test")
	s.AssertDischarge(c, httpbakery.WebBrowserInteractor{
		OpenWebBrowser: s.visitWebPage(c),
	})
}

func (s *dischargeSuite) visitWebPage(c *gc.C) func(u *url.URL) error {
	return func(u *url.URL) error {
		c.Logf("visiting %s", u)
		client := http.Client{}
		resp, err := client.Get(u.String())
		if err != nil {
			c.Logf("error: %s", err)
			return err
		}
		defer resp.Body.Close()
		c.Logf("status %s", resp.Status)
		if resp.StatusCode != http.StatusOK {
			return errgo.Newf("bad status %q", resp.Status)
		}
		return nil
	}
}
