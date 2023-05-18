// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package identity_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery"
	"github.com/juju/aclstore/v2/aclclient"
	"github.com/juju/loggo"
	"github.com/juju/qthttptest"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/httprequest.v1"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/static"
	"github.com/canonical/candid/internal/auth"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/internal/debug"
	"github.com/canonical/candid/internal/discharger"
	"github.com/canonical/candid/internal/identity"
	v1 "github.com/canonical/candid/internal/v1"
	"github.com/canonical/candid/params"
	"github.com/canonical/candid/store"
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
	h, err := identity.New(identity.ServerParams{
		Store:        s.store.Store,
		MeetingStore: s.store.MeetingStore,
	}, nil)
	c.Assert(err, qt.ErrorMatches, `identity server must serve at least one version of the API`)
	c.Assert(h, qt.IsNil)
}

type versionResponse struct {
	Version string
	Path    string
}

func (s *serverSuite) TestNewServerWithVersions(c *qt.C) {
	serveVersion := func(vers string) identity.NewAPIHandlerFunc {
		return func(identity.HandlerParams) ([]httprequest.Handler, error) {
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
					c.Assert(err, qt.IsNil)
				},
			}}, nil
		}
	}

	h, err := identity.New(identity.ServerParams{
		Store:        s.store.Store,
		MeetingStore: s.store.MeetingStore,
		ACLStore:     s.store.ACLStore,
	}, map[string]identity.NewAPIHandlerFunc{
		"version1": serveVersion("version1"),
	})
	c.Assert(err, qt.IsNil)
	defer h.Close()
	assertServesVersion(c, h, "version1")
	assertDoesNotServeVersion(c, h, "version2")
	assertDoesNotServeVersion(c, h, "version3")

	h, err = identity.New(identity.ServerParams{
		Store:        s.store.Store,
		MeetingStore: s.store.MeetingStore,
		ACLStore:     s.store.ACLStore,
	}, map[string]identity.NewAPIHandlerFunc{
		"version1": serveVersion("version1"),
		"version2": serveVersion("version2"),
	})
	c.Assert(err, qt.IsNil)
	defer h.Close()
	assertServesVersion(c, h, "version1")
	assertServesVersion(c, h, "version2")
	assertDoesNotServeVersion(c, h, "version3")

	h, err = identity.New(identity.ServerParams{
		Store:        s.store.Store,
		MeetingStore: s.store.MeetingStore,
		ACLStore:     s.store.ACLStore,
	}, map[string]identity.NewAPIHandlerFunc{
		"version1": serveVersion("version1"),
		"version2": serveVersion("version2"),
		"version3": serveVersion("version3"),
	})
	c.Assert(err, qt.IsNil)
	defer h.Close()
	assertServesVersion(c, h, "version1")
	assertServesVersion(c, h, "version2")
	assertServesVersion(c, h, "version3")
}

func (s *serverSuite) TestServerHasAccessControlAllowHeaders(c *qt.C) {
	impl := map[string]identity.NewAPIHandlerFunc{
		"/a": func(identity.HandlerParams) ([]httprequest.Handler, error) {
			return []httprequest.Handler{{
				Method: "GET",
				Path:   "/a",
				Handle: func(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
				},
			}}, nil
		},
	}

	h, err := identity.New(identity.ServerParams{
		Store:        s.store.Store,
		MeetingStore: s.store.MeetingStore,
		ACLStore:     s.store.ACLStore,
	}, impl)
	c.Assert(err, qt.IsNil)
	defer h.Close()
	rec := qthttptest.DoRequest(c, qthttptest.DoRequestParams{
		Handler: h,
		URL:     "/a",
	})
	c.Assert(rec.Code, qt.Equals, http.StatusOK)
	c.Assert(len(rec.HeaderMap["Access-Control-Allow-Origin"]), qt.Equals, 1)
	c.Assert(rec.HeaderMap["Access-Control-Allow-Origin"][0], qt.Equals, "*")
	c.Assert(len(rec.HeaderMap["Access-Control-Allow-Headers"]), qt.Equals, 1)
	c.Assert(rec.HeaderMap["Access-Control-Allow-Headers"][0], qt.Equals, "Bakery-Protocol-Version, Macaroons, X-Requested-With, Content-Type")
	c.Assert(len(rec.HeaderMap["Access-Control-Allow-Origin"]), qt.Equals, 1)
	c.Assert(rec.HeaderMap["Access-Control-Allow-Origin"][0], qt.Equals, "*")
	c.Assert(len(rec.HeaderMap["Access-Control-Cache-Max-Age"]), qt.Equals, 1)
	c.Assert(rec.HeaderMap["Access-Control-Cache-Max-Age"][0], qt.Equals, "600")

	rec = qthttptest.DoRequest(c, qthttptest.DoRequestParams{
		Handler: h,
		URL:     "/a/",
		Method:  "OPTIONS",
		Header:  http.Header{"Origin": []string{"MyHost"}},
	})
	c.Assert(rec.Code, qt.Equals, http.StatusOK)
	c.Assert(len(rec.HeaderMap["Access-Control-Allow-Origin"]), qt.Equals, 1)
	c.Assert(rec.HeaderMap["Access-Control-Allow-Origin"][0], qt.Equals, "*")
}

func (s *serverSuite) TestServerPanicRecovery(c *qt.C) {
	candidtest.LogTo(c)
	w := new(loggo.TestWriter)
	loggo.RegisterWriter("test", w)
	impl := map[string]identity.NewAPIHandlerFunc{
		"/a": func(identity.HandlerParams) ([]httprequest.Handler, error) {
			return []httprequest.Handler{{
				Method: "GET",
				Path:   "/a",
				Handle: func(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
					panic("test panic")
				},
			}}, nil
		},
	}

	h, err := identity.New(identity.ServerParams{
		Store:        s.store.Store,
		MeetingStore: s.store.MeetingStore,
		ACLStore:     s.store.ACLStore,
	}, impl)
	c.Assert(err, qt.IsNil)
	defer h.Close()
	qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
		Handler:      h,
		URL:          "/a",
		ExpectStatus: http.StatusInternalServerError,
		ExpectBody: params.Error{
			Code:    "panic",
			Message: "test panic",
		},
	})
	assertLogMatches(c, w.Log(), loggo.ERROR, `PANIC!: test panic(.|\n)+`)
}

func (s *serverSuite) TestServerStaticFiles(c *qt.C) {
	serveVersion := func(vers string) identity.NewAPIHandlerFunc {
		return func(identity.HandlerParams) ([]httprequest.Handler, error) {
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
					c.Assert(err, qt.IsNil)
				},
			}}, nil
		}
	}
	path := c.Mkdir()
	h, err := identity.New(identity.ServerParams{
		Store:            s.store.Store,
		MeetingStore:     s.store.MeetingStore,
		StaticFileSystem: http.Dir(path),
		ACLStore:         s.store.ACLStore,
	}, map[string]identity.NewAPIHandlerFunc{
		"version1": serveVersion("version1"),
	})
	c.Assert(err, qt.IsNil)
	defer h.Close()

	f, err := os.Create(filepath.Join(path, "file"))
	c.Assert(err, qt.IsNil)
	fmt.Fprintf(f, "test file")
	f.Close()

	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/static/file", nil)
	c.Assert(err, qt.IsNil)
	h.ServeHTTP(rr, req)
	c.Assert(rr.Code, qt.Equals, http.StatusOK, qt.Commentf("%d: %s", rr.Code, rr.Body.String()))
	c.Assert(rr.Body.String(), qt.Equals, "test file")
}

func assertServesVersion(c *qt.C, h http.Handler, vers string) {
	path := vers
	if path != "" {
		path = "/" + path
	}
	qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
		Handler: h,
		URL:     path + "/some/path",
		ExpectBody: versionResponse{
			Version: vers,
			Path:    "/" + vers + "/some/path",
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

type fullServerSuite struct {
	store *candidtest.Store
	srv   *candidtest.Server
}

func (s *fullServerSuite) Init(c *qt.C) {
	s.store = candidtest.NewStore()
	sp := s.store.ServerParams()
	sp.IdentityProviders = []idp.IdentityProvider{
		static.NewIdentityProvider(static.Params{
			Name: "test",
		}),
	}
	s.srv = candidtest.NewServer(c, sp, map[string]identity.NewAPIHandlerFunc{
		"debug":      debug.NewAPIHandler,
		"discharger": discharger.NewAPIHandler,
		"v1":         v1.NewAPIHandler,
	})
}

func (s *fullServerSuite) TestUserGroups(c *qt.C) {
	ctx := context.Background()
	err := s.store.Store.UpdateIdentity(
		ctx,
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("test", "bob"),
			Username:   "bob",
			Groups:     []string{"g4"},
		},
		store.Update{
			store.Username: store.Set,
			store.Groups:   store.Set,
		},
	)
	c.Assert(err, qt.IsNil)

	client := s.srv.AdminIdentityClient(false)
	groups, err := client.UserGroups(ctx, &params.UserGroupsRequest{
		Username: "bob",
	})
	c.Assert(err, qt.IsNil)
	c.Assert(groups, qt.DeepEquals, []string{"g1", "g2", "g3", "g4"})
}

func (s *fullServerSuite) TestACL(c *qt.C) {
	client := aclclient.New(aclclient.NewParams{
		BaseURL: s.srv.URL + "/acl",
		Doer:    s.srv.AdminClient(),
	})
	acl, err := client.Get(context.Background(), "read-user")
	c.Assert(err, qt.IsNil)
	c.Assert(acl, qt.DeepEquals, []string{auth.AdminUsername})
	err = client.Add(context.Background(), "read-user", []string{"test-1"})
	c.Assert(err, qt.IsNil)
	acl, err = client.Get(context.Background(), "read-user")
	c.Assert(err, qt.IsNil)
	c.Assert(acl, qt.DeepEquals, []string{auth.AdminUsername, "test-1"})
	err = client.Set(context.Background(), "read-user", []string{"test-2"})
	c.Assert(err, qt.IsNil)
	acl, err = client.Get(context.Background(), "read-user")
	c.Assert(err, qt.IsNil)
	c.Assert(acl, qt.DeepEquals, []string{"test-2"})
}

func (s *fullServerSuite) TestACLMACARAQResponse(c *qt.C) {
	resp, err := http.Get(s.srv.URL + "/acl/read-user")
	c.Assert(err, qt.IsNil)
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, qt.IsNil)
	var herr httpbakery.Error
	err = json.Unmarshal(buf, &herr)
	c.Assert(err, qt.IsNil)
	c.Assert(herr.Code, qt.Equals, httpbakery.ErrDischargeRequired)
	c.Assert(herr.Info, qt.Not(qt.IsNil))
	c.Assert(herr.Info.MacaroonPath, qt.Equals, "../")
}

func assertLogMatches(c *qt.C, entries []loggo.Entry, level loggo.Level, msg string) {
	pat := regexp.MustCompile(msg)
	for _, e := range entries {
		if e.Level == level && pat.MatchString(e.Message) {
			return
		}
	}
	c.Fatalf("no message found in log %#v matching %v: %q", entries, level, msg)
}
