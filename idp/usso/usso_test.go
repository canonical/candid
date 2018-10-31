// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package usso_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/candid/config"
	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idptest"
	"github.com/CanonicalLtd/candid/idp/idputil"
	"github.com/CanonicalLtd/candid/idp/usso"
	"github.com/CanonicalLtd/candid/idp/usso/internal/mockusso"
	"github.com/CanonicalLtd/candid/store"
)

type ussoSuite struct {
	idptest.Suite
	mockUSSOSuite mockusso.Suite

	idp idp.IdentityProvider
}

var _ = gc.Suite(&ussoSuite{})

func (s *ussoSuite) SetUpSuite(c *gc.C) {
	s.Suite.SetUpSuite(c)
	s.mockUSSOSuite.SetUpSuite(c)
}

func (s *ussoSuite) TearDownSuite(c *gc.C) {
	s.mockUSSOSuite.TearDownSuite(c)
	s.Suite.TearDownSuite(c)
}

func (s *ussoSuite) SetUpTest(c *gc.C) {
	s.Suite.SetUpTest(c)
	s.mockUSSOSuite.SetUpTest(c)
	s.idp = usso.NewIdentityProvider(usso.Params{})
	err := s.idp.Init(s.Ctx, s.InitParams(c, "https://idp.test"))
	c.Assert(err, gc.Equals, nil)
}

func (s *ussoSuite) TearDownTest(c *gc.C) {
	s.mockUSSOSuite.TearDownTest(c)
	s.Suite.TearDownTest(c)
}

func (s *ussoSuite) TestConfig(c *gc.C) {
	configYaml := `
identity-providers:
 - type: usso
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(configYaml), &conf)
	c.Assert(err, gc.Equals, nil)
	c.Assert(conf.IdentityProviders, gc.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), gc.Equals, "usso")
}

func (s *ussoSuite) TestName(c *gc.C) {
	c.Assert(s.idp.Name(), gc.Equals, "usso")
}

func (s *ussoSuite) TestDescription(c *gc.C) {
	c.Assert(s.idp.Description(), gc.Equals, "Ubuntu SSO")
}

func (s *ussoSuite) TestInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, true)
}

func (s *ussoSuite) TestURL(c *gc.C) {
	c.Assert(s.idp.URL("1"), gc.Equals, "https://idp.test/login?id=1")
}

func (s *ussoSuite) TestRedirect(c *gc.C) {
	u, err := url.Parse(s.ussoURL(c, s.Ctx, "1"))
	c.Assert(err, gc.Equals, nil)
	c.Assert(u.Host, gc.Equals, "login.ubuntu.com")
	c.Assert(u.Path, gc.Equals, "/+openid")
	q := u.Query()
	c.Assert(q, jc.DeepEquals, url.Values{
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

func (s *ussoSuite) TestRedirectWithLaunchpadTeams(c *gc.C) {
	s.idp = usso.NewIdentityProvider(usso.Params{LaunchpadTeams: []string{"myteam1", "myteam2"}})
	err := s.idp.Init(s.Ctx, s.InitParams(c, "https://idp.test"))
	c.Assert(err, gc.Equals, nil)
	u, err := url.Parse(s.ussoURL(c, s.Ctx, "1"))
	c.Assert(err, gc.Equals, nil)
	c.Assert(u.Host, gc.Equals, "login.ubuntu.com")
	c.Assert(u.Path, gc.Equals, "/+openid")
	q := u.Query()
	c.Assert(q, jc.DeepEquals, url.Values{
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

func (s *ussoSuite) TestHandleSuccess(c *gc.C) {
	s.mockUSSOSuite.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.mockUSSOSuite.MockUSSO.SetLoginUser("test")
	resp := s.roundTrip(c, s.ussoURL(c, s.Ctx, "2"))
	defer resp.Body.Close()
	s.get(c, s.Ctx, resp.Header.Get("Location"))
	s.AssertLoginSuccess(c, "test")
}

func (s *ussoSuite) TestHandleSuccessNoExtensions(c *gc.C) {
	err := s.Store.UpdateIdentity(
		s.Ctx,
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
	c.Assert(err, gc.Equals, nil)
	s.mockUSSOSuite.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.mockUSSOSuite.MockUSSO.SetLoginUser("test")
	s.mockUSSOSuite.MockUSSO.ExcludeExtensions()
	resp := s.roundTrip(c, s.ussoURL(c, s.Ctx, "3"))
	defer resp.Body.Close()
	s.get(c, s.Ctx, resp.Header.Get("Location"))
	s.AssertLoginSuccess(c, "test")
}

func (s *ussoSuite) TestHandleNoExtensionsNotFound(c *gc.C) {
	s.mockUSSOSuite.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.mockUSSOSuite.MockUSSO.SetLoginUser("test")
	s.mockUSSOSuite.MockUSSO.ExcludeExtensions()
	resp := s.roundTrip(c, s.ussoURL(c, s.Ctx, "4"))
	defer resp.Body.Close()
	s.get(c, s.Ctx, resp.Header.Get("Location"))
	s.AssertLoginFailureMatches(c, `invalid user: username not specified`)
}

func (s *ussoSuite) TestInteractiveLoginFromDifferentProvider(c *gc.C) {
	mockUSSO := mockusso.New("https://login.badplace.com")
	server := httptest.NewServer(mockUSSO)
	defer server.Close()
	s.PatchValue(&http.DefaultTransport, httptesting.URLRewritingTransport{
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
	s.get(c, s.Ctx, resp.Header.Get("Location"))
	s.AssertLoginFailureMatches(c, `.*OpenID response from unexpected endpoint "https://login.badplace.com/\+openid"`)
}

func (s *ussoSuite) TestHandleUpdateUserError(c *gc.C) {
	s.mockUSSOSuite.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test-",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.mockUSSOSuite.MockUSSO.SetLoginUser("test")
	resp := s.roundTrip(c, s.ussoURL(c, s.Ctx, "5"))
	defer resp.Body.Close()
	s.get(c, s.Ctx, resp.Header.Get("Location"))
	s.AssertLoginFailureMatches(c, `invalid user: invalid username "test-"`)
}

func (s *ussoSuite) TestRedirectFlowLogin(c *gc.C) {
	s.mockUSSOSuite.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.mockUSSOSuite.MockUSSO.SetLoginUser("test")
	resp := s.get(c, context.Background(), "/?return_to=http://example.com/callback&state=1234")
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, gc.HasLen, 1)
	c.Assert(cookies[0].Name, gc.Equals, idputil.RedirectCookieName)
	loc, err := resp.Location()
	c.Assert(err, gc.Equals, nil)
	resp = s.roundTrip(c, loc.String())
	defer resp.Body.Close()
	loc, err = resp.Location()
	c.Assert(err, gc.Equals, nil)
	loc.Scheme = ""
	loc.Host = ""
	req, err := http.NewRequest("GET", loc.String(), nil)
	c.Assert(err, gc.Equals, nil)
	req.AddCookie(cookies[0])
	s.do(context.Background(), req)
	s.AssertLoginSuccess(c, "test")
}

func (s *ussoSuite) TestRedirectFlowLoginInvalidCookie(c *gc.C) {
	s.mockUSSOSuite.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.mockUSSOSuite.MockUSSO.SetLoginUser("test")
	resp := s.get(c, context.Background(), "/?return_to=http://example.com/callback&state=1234")
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, gc.HasLen, 1)
	c.Assert(cookies[0].Name, gc.Equals, idputil.RedirectCookieName)
	loc, err := resp.Location()
	c.Assert(err, gc.Equals, nil)
	resp = s.roundTrip(c, loc.String())
	defer resp.Body.Close()
	loc, err = resp.Location()
	c.Assert(err, gc.Equals, nil)
	loc.Scheme = ""
	loc.Host = ""
	req, err := http.NewRequest("GET", loc.String(), nil)
	c.Assert(err, gc.Equals, nil)
	s.do(context.Background(), req)
	s.AssertLoginFailureMatches(c, "invalid cookie: http: named cookie not present")
}

func (s *ussoSuite) TestRedirectFlowLoginUserError(c *gc.C) {
	s.mockUSSOSuite.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test-",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.mockUSSOSuite.MockUSSO.SetLoginUser("test")
	resp := s.get(c, context.Background(), "/?return_to=http://example.com/callback&state=1234")
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, gc.HasLen, 1)
	c.Assert(cookies[0].Name, gc.Equals, idputil.RedirectCookieName)
	loc, err := resp.Location()
	c.Assert(err, gc.Equals, nil)
	resp = s.roundTrip(c, loc.String())
	defer resp.Body.Close()
	loc, err = resp.Location()
	c.Assert(err, gc.Equals, nil)
	loc.Scheme = ""
	loc.Host = ""
	req, err := http.NewRequest("GET", loc.String(), nil)
	c.Assert(err, gc.Equals, nil)
	req.AddCookie(cookies[0])
	s.do(context.Background(), req)
	s.AssertLoginFailureMatches(c, `invalid user: invalid username "test-"`)
}

func (s *ussoSuite) TestGetGroups(c *gc.C) {
	var lp *httptest.Server
	lp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Logf("path: %s", r.URL.Path)
		switch r.URL.Path {
		case "/people":
			r.ParseForm()
			c.Check(r.Form.Get("ws.op"), gc.Equals, "getByOpenIDIdentifier")
			c.Check(r.Form.Get("identifier"), gc.Equals, "https://login.launchpad.net/+id/test")
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
	c.Assert(err, gc.Equals, nil)
	c.Assert(groups, jc.DeepEquals, []string{"test1", "test2"})
}

// ussoURL gets a request addressed to the MockUSSO server with the given wait ID.
func (s *ussoSuite) ussoURL(c *gc.C, ctx context.Context, dischargeID string) string {
	resp := s.get(c, ctx, "/?id="+dischargeID)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusFound)
	loc, err := resp.Location()
	c.Assert(err, gc.Equals, nil)
	return loc.String()
}

// get performs a "GET" requests on the idp's Handle method with the
// given path.
func (s *ussoSuite) get(c *gc.C, ctx context.Context, path string) *http.Response {
	path = strings.TrimPrefix(path, "https://idp.test")
	req, err := http.NewRequest("GET", path, nil)
	c.Assert(err, gc.Equals, nil)
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
func (s *ussoSuite) roundTrip(c *gc.C, url string) *http.Response {
	req, err := http.NewRequest("GET", url, nil)
	c.Assert(err, gc.Equals, nil)
	resp, err := http.DefaultTransport.RoundTrip(req)
	c.Assert(err, gc.Equals, nil)
	return resp
}
