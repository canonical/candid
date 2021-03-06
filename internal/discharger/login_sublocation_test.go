// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger_test

import (
	"net/http"
	"path/filepath"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/candid/v2/idp"
	"github.com/canonical/candid/v2/idp/static"
	"github.com/canonical/candid/v2/internal/candidtest"
	"github.com/canonical/candid/v2/internal/discharger"
	"github.com/canonical/candid/v2/internal/identity"
)

const sublocationPath = "/sublocation"

var cookiePathTests = []struct {
	about        string
	skipLocation bool
}{{
	about:        "location in the cookie",
	skipLocation: false,
}, {
	about:        "location NOT in the cookie",
	skipLocation: true,
}}

func TestLoginCookiePath(t *testing.T) {
	c := qt.New(t)
	for _, test := range cookiePathTests {
		c.Run(test.about, func(c *qt.C) {
			// Set up the store and the server.
			store := candidtest.NewStore()
			p := store.ServerParams()
			p.IdentityProviders = []idp.IdentityProvider{
				static.NewIdentityProvider(static.Params{
					Name:   "test",
					Domain: "test",
					Icon:   "/static/static1.bmp",
				}),
			}
			p.SkipLocationForCookiePaths = test.skipLocation
			srv := candidtest.NewServerWithSublocation(c, p, map[string]identity.NewAPIHandlerFunc{
				"discharger": discharger.NewAPIHandler,
			}, sublocationPath)

			// Make the request.
			req, err := http.NewRequest("GET", sublocationPath+"/login", nil)
			c.Assert(err, qt.IsNil)
			req.Header.Set("Accept", "application/json")
			resp := srv.Do(c, req)
			defer resp.Body.Close()

			// Check the response.
			c.Assert(resp.StatusCode, qt.Equals, http.StatusOK)
			cookies := resp.Cookies()
			c.Assert(cookies, qt.Not(qt.HasLen), 0)
			for _, cookie := range cookies {
				dir := filepath.Dir(cookie.Path)
				if test.skipLocation {
					c.Assert(dir, qt.Not(qt.Equals), sublocationPath)
				} else {
					c.Assert(dir, qt.Equals, sublocationPath)
				}
			}
		})
	}
}
