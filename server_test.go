// Copyright 2014 Canonical Ltd.

package identity_test

import (
	"net/http"
	"testing"

	jujutesting "github.com/juju/testing"
	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	yaml "gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity"
	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	_ "github.com/CanonicalLtd/blues-identity/idp/agent"
	_ "github.com/CanonicalLtd/blues-identity/idp/test"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
	"github.com/CanonicalLtd/blues-identity/version"
)

func TestPackage(t *testing.T) {
	jujutesting.MgoTestPackage(t, nil)
}

type serverSuite struct {
	idmtest.StoreSuite
}

var _ = gc.Suite(&serverSuite{})

func (s *serverSuite) TestNewServerWithNoVersions(c *gc.C) {
	h, err := identity.NewServer(identity.ServerParams{
		PrivateAddr: "localhost",
	})
	c.Assert(err, gc.ErrorMatches, `identity server must serve at least one version of the API`)
	c.Assert(h, gc.IsNil)
}

func (s *serverSuite) TestNewServerWithUnregisteredVersion(c *gc.C) {
	h, err := identity.NewServer(
		identity.ServerParams{
			Store:        s.Store,
			MeetingStore: s.MeetingStore,
			RootKeyStore: s.BakeryRootKeyStore,
			PrivateAddr:  "localhost",
		},
		"wrong",
	)
	c.Assert(err, gc.ErrorMatches, `unknown version "wrong"`)
	c.Assert(h, gc.IsNil)
}

type versionResponse struct {
	Version string
	Path    string
}

func (s *serverSuite) TestVersions(c *gc.C) {
	c.Assert(identity.Versions(), gc.DeepEquals, []string{"debug", "discharger", "v1"})
}

func (s *serverSuite) TestNewServerWithVersions(c *gc.C) {
	h, err := identity.NewServer(
		identity.ServerParams{
			Store:        s.Store,
			MeetingStore: s.MeetingStore,
			RootKeyStore: s.BakeryRootKeyStore,
			PrivateAddr:  "localhost",
		},
		identity.Debug,
	)
	c.Assert(err, gc.IsNil)
	defer h.Close()

	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      h,
		URL:          "/debug/info",
		ExpectStatus: http.StatusOK,
		ExpectBody:   version.VersionInfo,
	})
	assertDoesNotServeVersion(c, h, "v0")
}

func (s *serverSuite) TestNewServerRemovesAgentIDP(c *gc.C) {
	var conf config.Config
	err := yaml.Unmarshal([]byte(`{"identity-providers": [{"type":"agent"},{"type":"test","name":"test"}]}`), &conf)
	c.Assert(err, gc.IsNil)
	idps := make([]idp.IdentityProvider, len(conf.IdentityProviders))
	for i, idp := range conf.IdentityProviders {
		idps[i] = idp.IdentityProvider
	}
	// The agent identity provider will error on initialisation if it
	// is not removed from the set.
	h, err := identity.NewServer(
		identity.ServerParams{
			Store:             s.Store,
			MeetingStore:      s.MeetingStore,
			RootKeyStore:      s.BakeryRootKeyStore,
			PrivateAddr:       "localhost",
			IdentityProviders: idps,
		},
		identity.V1,
	)
	c.Assert(err, gc.IsNil)
	h.Close()
}

func assertServesVersion(c *gc.C, h http.Handler, vers string) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: h,
		URL:     "/" + vers + "/some/path",
		ExpectBody: versionResponse{
			Version: vers,
			Path:    "/some/path",
		},
	})
}

func assertDoesNotServeVersion(c *gc.C, h http.Handler, vers string) {
	rec := httptesting.DoRequest(c, httptesting.DoRequestParams{
		Handler: h,
		URL:     "/" + vers + "/some/path",
	})
	c.Assert(rec.Code, gc.Equals, http.StatusNotFound)
}
