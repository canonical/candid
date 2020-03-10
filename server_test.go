// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package candid_test

import (
	"net/http"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/juju/qthttptest"
	yaml "gopkg.in/yaml.v2"

	"github.com/canonical/candid"
	"github.com/canonical/candid/config"
	"github.com/canonical/candid/idp"
	_ "github.com/canonical/candid/idp/agent"
	_ "github.com/canonical/candid/idp/static"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/version"
)

func TestServer(t *testing.T) {
	qtsuite.Run(qt.New(t), &serverSuite{})
}

type serverSuite struct {
	store *candidtest.Store
}

func (s *serverSuite) Init(c *qt.C) {
	s.store = candidtest.NewStore()
}

func (s *serverSuite) TestNewServerWithNoVersions(c *qt.C) {
	h, err := candid.NewServer(candid.ServerParams(s.store.ServerParams()))
	c.Assert(err, qt.ErrorMatches, `identity server must serve at least one version of the API`)
	c.Assert(h, qt.IsNil)
}

func (s *serverSuite) TestNewServerWithUnregisteredVersion(c *qt.C) {
	h, err := candid.NewServer(
		candid.ServerParams(s.store.ServerParams()),
		"wrong",
	)
	c.Assert(err, qt.ErrorMatches, `unknown version "wrong"`)
	c.Assert(h, qt.IsNil)
}

type versionResponse struct {
	Version string
	Path    string
}

func (s *serverSuite) TestVersions(c *qt.C) {
	c.Assert(candid.Versions(), qt.DeepEquals, []string{"debug", "discharger", "v1"})
}

func (s *serverSuite) TestNewServerWithVersions(c *qt.C) {
	h, err := candid.NewServer(
		candid.ServerParams(s.store.ServerParams()),
		candid.Debug,
	)
	c.Assert(err, qt.Equals, nil)
	defer h.Close()

	qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
		Handler:      h,
		URL:          "/debug/info",
		ExpectStatus: http.StatusOK,
		ExpectBody:   version.VersionInfo,
	})
	assertDoesNotServeVersion(c, h, "v0")
}

func (s *serverSuite) TestNewServerRemovesAgentIDP(c *qt.C) {
	var conf config.Config
	err := yaml.Unmarshal([]byte(`{"identity-providers": [{"type":"agent"},{"type":"static","name":"test"}]}`), &conf)
	c.Assert(err, qt.Equals, nil)
	idps := make([]idp.IdentityProvider, len(conf.IdentityProviders))
	for i, idp := range conf.IdentityProviders {
		idps[i] = idp.IdentityProvider
	}
	sp := candid.ServerParams(s.store.ServerParams())
	sp.IdentityProviders = idps
	h, err := candid.NewServer(sp, candid.V1)
	c.Assert(err, qt.Equals, nil)
	h.Close()
}

func assertServesVersion(c *qt.C, h http.Handler, vers string) {
	qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
		Handler: h,
		URL:     "/" + vers + "/some/path",
		ExpectBody: versionResponse{
			Version: vers,
			Path:    "/some/path",
		},
	})
}

func assertDoesNotServeVersion(c *qt.C, h http.Handler, vers string) {
	rec := qthttptest.DoRequest(c, qthttptest.DoRequestParams{
		Handler: h,
		URL:     "/" + vers + "/some/path",
	})
	c.Assert(rec.Code, qt.Equals, http.StatusNotFound)
}
