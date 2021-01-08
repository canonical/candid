// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger_test

import (
	"net/http"
	"path/filepath"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/static"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/internal/discharger"
	"github.com/canonical/candid/internal/identity"
)

const sublocationPath = "/sublocation"

func TestLoginWithSublocation(t *testing.T) {
	qtsuite.Run(qt.New(t), &loginSuite{})
}

type loginSuite struct {
	srv *candidtest.Server
}

func (s *loginSuite) Init(c *qt.C) {
	store := candidtest.NewStore()
	sp := store.ServerParams()
	sp.IdentityProviders = []idp.IdentityProvider{
		static.NewIdentityProvider(static.Params{
			Name:   "test",
			Domain: "test",
			Icon:   "/static/static1.bmp",
		}),
	}
	s.srv = candidtest.NewServerWithSublocation(c, sp, map[string]identity.NewAPIHandlerFunc{
		"discharger": discharger.NewAPIHandler,
	}, sublocationPath)
}

func (s *loginSuite) TestLoginCookiePathContainsServerSublocation(c *qt.C) {
	req, err := http.NewRequest("GET", sublocationPath+"/login", nil)
	c.Assert(err, qt.IsNil)
	req.Header.Set("Accept", "application/json")
	resp := s.srv.Do(c, req)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, qt.Equals, http.StatusOK)

	cookies := resp.Cookies()
	c.Assert(len(cookies) > 0, qt.IsTrue)

	for _, cookie := range cookies {
		dir := filepath.Dir(cookie.Path)
		c.Assert(dir, qt.Equals, sublocationPath)
	}
}
