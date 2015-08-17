// Copyright 2014 Canonical Ltd.

package identity_test

import (
	"encoding/json"
	"net/http"

	"github.com/juju/httprequest"
	"github.com/juju/testing"
	"github.com/juju/testing/httptesting"
	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

type serverSuite struct {
	testing.IsolatedMgoSuite
}

var _ = gc.Suite(&serverSuite{})

func (s *serverSuite) TestNewServerWithNoVersions(c *gc.C) {
	h, err := identity.New(s.Session.DB("foo"), identity.ServerParams{}, nil)
	c.Assert(err, gc.ErrorMatches, `identity server must serve at least one version of the API`)
	c.Assert(h, gc.IsNil)
}

type versionResponse struct {
	Version string
	Path    string
}

func (s *serverSuite) TestNewServerWithVersions(c *gc.C) {
	db := s.Session.DB("foo")
	serveVersion := func(vers string) identity.NewAPIHandlerFunc {
		return func(*store.Pool, identity.ServerParams, []identity.IdentityProvider) ([]httprequest.Handler, error) {
			return []httprequest.Handler{{
				Method: "GET",
				Path:   "/" + vers + "/*path",
				Handle: func(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
					w.Header().Set("Content-Type", "application/json")
					response := versionResponse{
						Version: vers,
						Path:    req.URL.Path,
					}
					enc := json.NewEncoder(w)
					err := enc.Encode(response)
					c.Assert(err, gc.IsNil)
				},
			}}, nil
		}
	}

	h, err := identity.New(db, identity.ServerParams{}, map[string]identity.NewAPIHandlerFunc{
		"version1": serveVersion("version1"),
	})
	c.Assert(err, gc.IsNil)
	assertServesVersion(c, h, "version1")
	assertDoesNotServeVersion(c, h, "version2")
	assertDoesNotServeVersion(c, h, "version3")

	h, err = identity.New(db, identity.ServerParams{}, map[string]identity.NewAPIHandlerFunc{
		"version1": serveVersion("version1"),
		"version2": serveVersion("version2"),
	})
	c.Assert(err, gc.IsNil)
	assertServesVersion(c, h, "version1")
	assertServesVersion(c, h, "version2")
	assertDoesNotServeVersion(c, h, "version3")

	h, err = identity.New(db, identity.ServerParams{}, map[string]identity.NewAPIHandlerFunc{
		"version1": serveVersion("version1"),
		"version2": serveVersion("version2"),
		"version3": serveVersion("version3"),
	})
	c.Assert(err, gc.IsNil)
	assertServesVersion(c, h, "version1")
	assertServesVersion(c, h, "version2")
	assertServesVersion(c, h, "version3")
}

func assertServesVersion(c *gc.C, h http.Handler, vers string) {
	path := vers
	if path != "" {
		path = "/" + path
	}
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: h,
		URL:     path + "/some/path",
		ExpectBody: versionResponse{
			Version: vers,
			Path:    "/" + vers + "/some/path",
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
