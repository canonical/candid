// Copyright 2014 Canonical Ltd.

package identity_test

import (
	"net/http"
	"testing"

	jujutesting "github.com/juju/testing"
	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity"
	"github.com/CanonicalLtd/blues-identity/version"
)

func TestPackage(t *testing.T) {
	jujutesting.MgoTestPackage(t, nil)
}

type serverSuite struct {
	jujutesting.IsolatedMgoSuite
}

var _ = gc.Suite(&serverSuite{})

func (s *serverSuite) TestNewServerWithNoVersions(c *gc.C) {
	h, err := identity.NewServer(s.Session.DB("foo"), identity.ServerParams{
		PrivateAddr: "localhost",
	})
	c.Assert(err, gc.ErrorMatches, `identity server must serve at least one version of the API`)
	c.Assert(h, gc.IsNil)
}

func (s *serverSuite) TestNewServerWithUnregisteredVersion(c *gc.C) {
	h, err := identity.NewServer(s.Session.DB("foo"), identity.ServerParams{
		PrivateAddr: "localhost",
	}, "wrong")
	c.Assert(err, gc.ErrorMatches, `unknown version "wrong"`)
	c.Assert(h, gc.IsNil)
}

type versionResponse struct {
	Version string
	Path    string
}

func (s *serverSuite) TestVersions(c *gc.C) {
	c.Assert(identity.Versions(), gc.DeepEquals, []string{"v1"})
}

func (s *serverSuite) TestNewServerWithVersions(c *gc.C) {
	h, err := identity.NewServer(s.Session.DB("foo"),
		identity.ServerParams{
			MaxMgoSessions: 300,
			PrivateAddr:    "localhost",
		},
		identity.V1)
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
