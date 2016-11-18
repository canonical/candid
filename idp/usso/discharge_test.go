// Copyright 2015 Canonical Ltd.

package usso_test

import (
	"net/http"
	"net/url"

	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/usso"
	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/mockusso"
)

type dischargeSuite struct {
	idptest.DischargeSuite
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
	s.IDPs = []idp.IdentityProvider{
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
	s.AssertDischarge(c, idptest.VisitorFunc(s.visitWebPage), checkers.New(
		checkers.TimeBefore,
	))
}

func (s *dischargeSuite) visitWebPage(u *url.URL) error {
	client := http.Client{
		Transport: s.RoundTripper,
	}
	resp, err := client.Get(u.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errgo.Newf("bad status %q", resp.Status)
	}
	return nil
}
