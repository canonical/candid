// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package usso_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/juju/testing/httptesting"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/candid/config"
	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idputil"
	"github.com/CanonicalLtd/candid/idp/idptest"
	"github.com/CanonicalLtd/candid/idp/usso"
	mockusso "github.com/CanonicalLtd/candid/idp/usso/internal/qtmockusso"
	candidtest "github.com/CanonicalLtd/candid/internal/qtcandidtest"
	"github.com/CanonicalLtd/candid/store"
)

type ussoSuite struct {
	idptest *idptest.Fixture

	idp idp.IdentityProvider
}

func TestUSSO(t *testing.T) {
	qtsuite.Run(qt.New(t), &ussoSuite{})
}

func (s *ussoSuite) Init(c *qt.C) {
	s.idptest = idptest.NewFixture(c, candidtest.NewStore())
	s.idp = usso.NewIdentityProvider(usso.Params{})
	err := s.idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, "https://idp.test"))
	c.Assert(err, qt.Equals, nil)
}

func (s *ussoSuite) TestConfig(c *qt.C) {
	configYaml := `
identity-providers:
 - type: usso
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(configYaml), &conf)
	c.Assert(err, qt.Equals, nil)
	c.Assert(conf.IdentityProviders, qt.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), qt.Equals, "usso")
}

func (s *ussoSuite) TestName(c *qt.C) {
	c.Assert(s.idp.Name(), qt.Equals, "usso")
}

func (s *ussoSuite) TestDescription(c *qt.C) {
	c.Assert(s.idp.Description(), qt.Equals, "Ubuntu SSO")
}

func (s *ussoSuite) TestInteractive(c *qt.C) {
	c.Assert(s.idp.Interactive(), qt.Equals, true)
}

func (s *ussoSuite) TestURL(c *qt.C) {
	c.Assert(s.idp.URL("1"), qt.Equals, "https://idp.test/login?id=1")
}

func (s *ussoSuite) TestRedirect(c *qt.C) {
	u, err := url.Parse(s.ussoURL(c, s.idptest.Ctx, "1"))
	c.Assert(err, qt.Equals, nil)
	c.Assert(u.Host, qt.Equals, "login.ubuntu.com")
	c.Assert(u.Path, qt.Equals, "/+openid")
	q := u.Query()
	c.Assert(q, qt.DeepEquals, url.Values{
		"openid.ns":            []string{"http://specs.openid.net/auth/2.0"},
		"openid.claimed_id":    []string{"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.identity":      []string{"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.mode":          []string{"checkid_setup"},
		"openid.realm":         []string{"https://idp.test/callback"},
		"openid.return_to":     []string{"https://idp.test/callback?id=1"},
		"openid.ns.sreg":       []string{"http://openid.net/extensions/sreg/1.1"},
		"openid.sreg.required": []string{"email,fullname,nickname"},
	})
}

func (s *ussoSuite) TestRedirectWithLaunchpadTeams(c *qt.C) {
	s.idp = usso.NewIdentityProvider(usso.Params{LaunchpadTeams: []string{"myteam1", "myteam2"}})
	err := s.idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, "https://idp.test"))
	c.Assert(err, qt.Equals, nil)
	u, err := url.Parse(s.ussoURL(c, s.idptest.Ctx, "1"))
	c.Assert(err, qt.Equals, nil)
	c.Assert(u.Host, qt.Equals, "login.ubuntu.com")
	c.Assert(u.Path, qt.Equals, "/+openid")
	q := u.Query()
	c.Assert(q, qt.DeepEquals, url.Values{
		"openid.ns":                  []string{"http://specs.openid.net/auth/2.0"},
		"openid.claimed_id":          []string{"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.identity":            []string{"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.mode":                []string{"checkid_setup"},
		"openid.realm":               []string{"https://idp.test/callback"},
		"openid.return_to":           []string{"https://idp.test/callback?id=1"},
		"openid.ns.lp":               []string{"http://ns.launchpad.net/2007/openid-teams"},
		"openid.lp.query_membership": []string{"myteam1,myteam2"},
		"openid.ns.sreg":             []string{"http://openid.net/extensions/sreg/1.1"},
		"openid.sreg.required":       []string{"email,fullname,nickname"},
	})
}

func (s *ussoSuite) TestHandleSuccess(c *qt.C) {
	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()
	ussoSrv.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	ussoSrv.MockUSSO.SetLoginUser("test")
	resp := s.roundTrip(c, s.ussoURL(c, s.idptest.Ctx, "2"))
	defer resp.Body.Close()
	s.get(c, s.idptest.Ctx, resp.Header.Get("Location"))
	s.idptest.AssertLoginSuccess(c, "test")
}

func (s *ussoSuite) TestHandleSuccessNoExtensions(c *qt.C) {
	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()
	err := s.idptest.Store.Store.UpdateIdentity(
		s.idptest.Ctx,
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("usso", "https://login.ubuntu.com/+id/test"),
			Username:   "test",
			Name:       "Test User",
			Email:      "test@example.com",
		},
		store.Update{
			store.Username: store.Set,
			store.Name:     store.Set,
			store.Email:    store.Set,
		},
	)
	c.Assert(err, qt.Equals, nil)
	ussoSrv.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	ussoSrv.MockUSSO.SetLoginUser("test")
	ussoSrv.MockUSSO.ExcludeExtensions()
	resp := s.roundTrip(c, s.ussoURL(c, s.idptest.Ctx, "3"))
	defer resp.Body.Close()
	s.get(c, s.idptest.Ctx, resp.Header.Get("Location"))
	s.idptest.AssertLoginSuccess(c, "test")
}

func (s *ussoSuite) TestHandleNoExtensionsNotFound(c *qt.C) {
	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()
	ussoSrv.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	ussoSrv.MockUSSO.SetLoginUser("test")
	ussoSrv.MockUSSO.ExcludeExtensions()
	resp := s.roundTrip(c, s.ussoURL(c, s.idptest.Ctx, "4"))
	defer resp.Body.Close()
	s.get(c, s.idptest.Ctx, resp.Header.Get("Location"))
	s.idptest.AssertLoginFailureMatches(c, `invalid user: username not specified`)
}

func (s *ussoSuite) TestInteractiveLoginFromDifferentProvider(c *qt.C) {
	mockUSSO := mockusso.New("https://login.badplace.com")
	server := httptest.NewServer(mockUSSO)
	defer server.Close()
	c.Patch(&http.DefaultTransport, httptesting.URLRewritingTransport{
		MatchPrefix:  "https://login.badplace.com",
		Replace:      server.URL,
		RoundTripper: http.DefaultTransport,
	})
	mockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
		Groups:   []string{"test1", "test2"},
	})
	mockUSSO.SetLoginUser("test")
	v := url.Values{}
	v.Set("openid.ns", "http://specs.openid.net/auth/2.0")
	v.Set("openid.mode", "checkid_setup")
	v.Set("openid.claimed_id", "https://login.badplace.com")
	v.Set("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
	v.Set("openid.return_to", "https://idp.test/callback")
	v.Set("openid.realm", "https://idp.test/callback")
	u := &url.URL{
		Scheme:   "https",
		Host:     "login.badplace.com",
		Path:     "/+openid",
		RawQuery: v.Encode(),
	}
	resp := s.roundTrip(c, u.String())
	defer resp.Body.Close()
	s.get(c, s.idptest.Ctx, resp.Header.Get("Location"))
	s.idptest.AssertLoginFailureMatches(c, `.*OpenID response from unexpected endpoint "https://login.badplace.com/\+openid"`)
}

func (s *ussoSuite) TestHandleUpdateUserError(c *qt.C) {
	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()
	ussoSrv.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test-",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	ussoSrv.MockUSSO.SetLoginUser("test")
	resp := s.roundTrip(c, s.ussoURL(c, s.idptest.Ctx, "5"))
	defer resp.Body.Close()
	s.get(c, s.idptest.Ctx, resp.Header.Get("Location"))
	s.idptest.AssertLoginFailureMatches(c, `invalid user: invalid username "test-"`)
}

func (s *ussoSuite) TestRedirectFlowLogin(c *qt.C) {
	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()
	ussoSrv.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	ussoSrv.MockUSSO.SetLoginUser("test")
	resp := s.get(c, context.Background(), "/?return_to=http://example.com/callback&state=1234")
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, qt.HasLen, 1)
	c.Assert(cookies[0].Name, qt.Equals, idputil.RedirectCookieName)
	loc, err := resp.Location()
	c.Assert(err, qt.Equals, nil)
	resp = s.roundTrip(c, loc.String())
	defer resp.Body.Close()
	loc, err = resp.Location()
	c.Assert(err, qt.Equals, nil)
	loc.Scheme = ""
	loc.Host = ""
	req, err := http.NewRequest("GET", loc.String(), nil)
	c.Assert(err, qt.Equals, nil)
	req.AddCookie(cookies[0])
	s.do(context.Background(), req)
	s.idptest.AssertLoginSuccess(c, "test")
}

func (s *ussoSuite) TestRedirectFlowLoginInvalidCookie(c *qt.C) {
	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()
	ussoSrv.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	ussoSrv.MockUSSO.SetLoginUser("test")
	resp := s.get(c, context.Background(), "/?return_to=http://example.com/callback&state=1234")
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, qt.HasLen, 1)
	c.Assert(cookies[0].Name, qt.Equals, idputil.RedirectCookieName)
	loc, err := resp.Location()
	c.Assert(err, qt.Equals, nil)
	resp = s.roundTrip(c, loc.String())
	defer resp.Body.Close()
	loc, err = resp.Location()
	c.Assert(err, qt.Equals, nil)
	loc.Scheme = ""
	loc.Host = ""
	req, err := http.NewRequest("GET", loc.String(), nil)
	c.Assert(err, qt.Equals, nil)
	s.do(context.Background(), req)
	s.idptest.AssertLoginFailureMatches(c, "invalid cookie: http: named cookie not present")
}

func (s *ussoSuite) TestRedirectFlowLoginUserError(c *qt.C) {
	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()
	ussoSrv.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test-",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	ussoSrv.MockUSSO.SetLoginUser("test")
	resp := s.get(c, context.Background(), "/?return_to=http://example.com/callback&state=1234")
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, qt.HasLen, 1)
	c.Assert(cookies[0].Name, qt.Equals, idputil.RedirectCookieName)
	loc, err := resp.Location()
	c.Assert(err, qt.Equals, nil)
	resp = s.roundTrip(c, loc.String())
	defer resp.Body.Close()
	loc, err = resp.Location()
	c.Assert(err, qt.Equals, nil)
	loc.Scheme = ""
	loc.Host = ""
	req, err := http.NewRequest("GET", loc.String(), nil)
	c.Assert(err, qt.Equals, nil)
	req.AddCookie(cookies[0])
	s.do(context.Background(), req)
	s.idptest.AssertLoginFailureMatches(c, `invalid user: invalid username "test-"`)
}

func (s *ussoSuite) TestGetGroups(c *qt.C) {
	var lp *httptest.Server
	lp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Logf("path: %s", r.URL.Path)
		switch r.URL.Path {
		case "/people":
			r.ParseForm()
			c.Check(r.Form.Get("ws.op"), qt.Equals, "getByOpenIDIdentifier")
			c.Check(r.Form.Get("identifier"), qt.Equals, "https://login.launchpad.net/+id/test")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"name": "test", "super_teams_collection_link": "https://api.launchpad.net/devel/test/super_teams"}`)
		case "/test/super_teams":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"total_size":3,"start":0,"entries": [{"name": "test1"},{"name":"test2"}]}`)
		}
	}))
	defer lp.Close()

	rt := httptesting.URLRewritingTransport{
		MatchPrefix:  "https://api.launchpad.net/devel",
		Replace:      lp.URL,
		RoundTripper: http.DefaultTransport,
	}
	savedTransport := http.DefaultTransport
	defer func() {
		http.DefaultTransport = savedTransport
	}()
	http.DefaultTransport = rt

	groups, err := s.idp.GetGroups(context.Background(), &store.Identity{
		ProviderID: store.MakeProviderIdentity("usso", "https://login.ubuntu.com/+id/test"),
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"test1", "test2"})
}

// ussoURL gets a request addressed to the MockUSSO server with the given wait ID.
func (s *ussoSuite) ussoURL(c *qt.C, ctx context.Context, dischargeID string) string {
	resp := s.get(c, ctx, "/?id="+dischargeID)
	c.Assert(resp.StatusCode, qt.Equals, http.StatusFound)
	loc, err := resp.Location()
	c.Assert(err, qt.Equals, nil)
	return loc.String()
}

// get performs a "GET" requests on the idp's Handle method with the
// given path.
func (s *ussoSuite) get(c *qt.C, ctx context.Context, path string) *http.Response {
	path = strings.TrimPrefix(path, "https://idp.test")
	req, err := http.NewRequest("GET", path, nil)
	c.Assert(err, qt.Equals, nil)
	return s.do(ctx, req)
}

func (s *ussoSuite) do(ctx context.Context, req *http.Request) *http.Response {
	rr := httptest.NewRecorder()
	req.ParseForm()
	s.idp.Handle(ctx, rr, req)
	return rr.Result()
}

// roundTrip uses http.DefaultTransport to perform a GET request as a
// single round trip to the given URL.
func (s *ussoSuite) roundTrip(c *qt.C, url string) *http.Response {
	req, err := http.NewRequest("GET", url, nil)
	c.Assert(err, qt.Equals, nil)
	resp, err := http.DefaultTransport.RoundTrip(req)
	c.Assert(err, qt.Equals, nil)
	return resp
}
