// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package usso_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/juju/qthttptest"
	"gopkg.in/yaml.v2"

	"github.com/canonical/candid/config"
	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/idptest"
	"github.com/canonical/candid/idp/idputil"
	"github.com/canonical/candid/idp/usso"
	"github.com/canonical/candid/idp/usso/internal/mockusso"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/store"
)

type ussoSuite struct {
	idptest *idptest.Fixture
	idp     idp.IdentityProvider
}

func TestUSSO(t *testing.T) {
	qtsuite.Run(qt.New(t), &ussoSuite{})
}

const idpPrefix = "http://idp.example.com"

func (s *ussoSuite) Init(c *qt.C) {
	s.idptest = idptest.NewFixture(c, candidtest.NewStore())
	s.idp = usso.NewIdentityProvider(usso.Params{})
	err := s.idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, idpPrefix))
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

func (s *ussoSuite) TestDomain(c *qt.C) {
	c.Assert(s.idp.Domain(), qt.Equals, "")
}

func (s *ussoSuite) TestDescription(c *qt.C) {
	c.Assert(s.idp.Description(), qt.Equals, "Ubuntu SSO")
}

func (s *ussoSuite) TestIconURL(c *qt.C) {
	c.Assert(s.idp.IconURL(), qt.Equals, "")
}

func (s *ussoSuite) TestAbsoluteIconURL(c *qt.C) {
	idp := usso.NewIdentityProvider(usso.Params{
		Icon: "https://www.example.com/icon.bmp",
	})
	err := idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, idpPrefix))
	c.Assert(err, qt.Equals, nil)
	c.Assert(idp.IconURL(), qt.Equals, "https://www.example.com/icon.bmp")
}

func (s *ussoSuite) TestRelativeIconURL(c *qt.C) {
	idp := usso.NewIdentityProvider(usso.Params{
		Icon: "/static/icon.bmp",
	})
	params := s.idptest.InitParams(c, idpPrefix)
	params.Location = "https://www.example.com/candid"
	err := idp.Init(s.idptest.Ctx, params)
	c.Assert(err, qt.Equals, nil)
	c.Assert(idp.IconURL(), qt.Equals, "https://www.example.com/candid/static/icon.bmp")
}

func (s *ussoSuite) TestInteractive(c *qt.C) {
	c.Assert(s.idp.Interactive(), qt.Equals, true)
}

func (s *ussoSuite) TestHidden(c *qt.C) {
	c.Assert(s.idp.Hidden(), qt.Equals, false)
}

func (s *ussoSuite) TestURL(c *qt.C) {
	c.Assert(s.idp.URL("1"), qt.Equals, "http://idp.example.com/login?state=1")
}

func (s *ussoSuite) TestRedirect(c *qt.C) {
	u := s.getRedirectURL(c, "/login")
	c.Assert(u.Host, qt.Equals, "login.ubuntu.com")
	c.Assert(u.Path, qt.Equals, "/+openid")
	q := u.Query()
	c.Assert(q.Get("openid.return_to"), qt.Matches, "http://idp.example.com/callback\\?state=[-_0-9A-Za-z]+")
	delete(q, "openid.return_to")
	c.Assert(q, qt.DeepEquals, url.Values{
		"openid.ns":            []string{"http://specs.openid.net/auth/2.0"},
		"openid.claimed_id":    []string{"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.identity":      []string{"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.mode":          []string{"checkid_setup"},
		"openid.realm":         []string{"http://idp.example.com/callback"},
		"openid.ns.sreg":       []string{"http://openid.net/extensions/sreg/1.1"},
		"openid.sreg.required": []string{"email,fullname,nickname"},
	})
}

func (s *ussoSuite) TestRedirectWithLaunchpadTeams(c *qt.C) {
	s.idp = usso.NewIdentityProvider(usso.Params{LaunchpadTeams: []string{"myteam1", "myteam2"}})
	err := s.idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, "http://idp.example.com"))
	c.Assert(err, qt.Equals, nil)

	u := s.getRedirectURL(c, "/login")
	c.Assert(u.Host, qt.Equals, "login.ubuntu.com")
	c.Assert(u.Path, qt.Equals, "/+openid")
	q := u.Query()
	c.Assert(q.Get("openid.return_to"), qt.Matches, "http://idp.example.com/callback\\?state=[-_0-9A-Za-z]+")
	delete(q, "openid.return_to")
	c.Assert(q, qt.DeepEquals, url.Values{
		"openid.ns":                  []string{"http://specs.openid.net/auth/2.0"},
		"openid.claimed_id":          []string{"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.identity":            []string{"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.mode":                []string{"checkid_setup"},
		"openid.realm":               []string{"http://idp.example.com/callback"},
		"openid.ns.lp":               []string{"http://ns.launchpad.net/2007/openid-teams"},
		"openid.lp.query_membership": []string{"myteam1,myteam2"},
		"openid.ns.sreg":             []string{"http://openid.net/extensions/sreg/1.1"},
		"openid.sreg.required":       []string{"email,fullname,nickname"},
	})
}

func (s *ussoSuite) getRedirectURL(c *qt.C, path string) *url.URL {
	client := idptest.NewClient(s.idp, s.idptest.Codec)
	client.SetLoginState(idputil.LoginState{
		ReturnTo: "http://result.example.com",
		State:    "1234",
		Expires:  time.Now().Add(10 * time.Minute),
	})
	resp, err := client.Get("/login")
	c.Assert(err, qt.Equals, nil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, qt.Equals, http.StatusFound)
	u, err := url.Parse(resp.Header.Get("Location"))
	c.Assert(err, qt.Equals, nil)
	return u
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

	id, err := s.idptest.DoInteractiveLogin(c, s.idp, idpPrefix+"/login", nil)
	c.Assert(err, qt.Equals, nil)
	candidtest.AssertEqualIdentity(c, id, &store.Identity{
		ProviderID: "usso:https://login.ubuntu.com/+id/test",
		Username:   "test",
		Name:       "Test User",
		Email:      "test@example.com",
	})
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

	id, err := s.idptest.DoInteractiveLogin(c, s.idp, idpPrefix+"/login", nil)
	c.Assert(err, qt.Equals, nil)
	candidtest.AssertEqualIdentity(c, id, &store.Identity{
		ProviderID: "usso:https://login.ubuntu.com/+id/test",
		Username:   "test",
		Name:       "Test User",
		Email:      "test@example.com",
	})
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

	id, err := s.idptest.DoInteractiveLogin(c, s.idp, idpPrefix+"/login", nil)
	c.Assert(err, qt.ErrorMatches, `invalid user: username not specified`)
	c.Assert(id, qt.IsNil)
}

func (s *ussoSuite) TestInteractiveLoginFromDifferentProvider(c *qt.C) {
	mockUSSO := mockusso.New("https://badplace.example.com")
	server := httptest.NewServer(mockUSSO)
	defer server.Close()
	c.Patch(&http.DefaultTransport, qthttptest.URLRewritingTransport{
		MatchPrefix:  "https://badplace.example.com",
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.ParseForm()
		s.idp.Handle(req.Context(), w, req)
	}))
	defer srv.Close()

	client := s.idptest.Client(c, idpPrefix, srv.URL, "https://result.example.com")
	cookie, state := s.idptest.LoginState(c, idputil.LoginState{
		ReturnTo: "https://result.example.com",
		State:    "1234",
		Expires:  time.Now().Add(10 * time.Minute),
	})
	u, err := url.Parse(idpPrefix)
	c.Assert(err, qt.Equals, nil)
	client.Jar.SetCookies(u, []*http.Cookie{cookie})

	mockUSSO.SetLoginUser("test")
	v := url.Values{}
	v.Set("openid.ns", "http://specs.openid.net/auth/2.0")
	v.Set("openid.mode", "checkid_setup")
	v.Set("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")
	v.Set("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
	v.Set("openid.return_to", idpPrefix+"/callback?state="+state)
	v.Set("openid.realm", idpPrefix+"/callback")
	u = &url.URL{
		Scheme:   "https",
		Host:     "badplace.example.com",
		Path:     "/+openid",
		RawQuery: v.Encode(),
	}
	resp, err := client.Get(u.String())
	c.Assert(err, qt.Equals, nil)
	defer resp.Body.Close()
	id, err := s.idptest.ParseResponse(c, resp)
	c.Assert(err, qt.ErrorMatches, `OpenID response from unexpected endpoint "https://badplace.example.com/\+openid"`)
	c.Assert(id, qt.IsNil)
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

	id, err := s.idptest.DoInteractiveLogin(c, s.idp, idpPrefix+"/login", nil)
	c.Assert(err, qt.ErrorMatches, `invalid user: invalid username "test-"`)
	c.Assert(id, qt.IsNil)
}

func (s *ussoSuite) TestInvalidCookie(c *qt.C) {
	client := idptest.NewClient(s.idp, s.idptest.Codec)
	resp, err := client.Get("/callback")
	c.Assert(err, qt.Equals, nil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, qt.Equals, http.StatusBadRequest)
}

func (s *ussoSuite) TestGetGroups(c *qt.C) {
	lp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	rt := qthttptest.URLRewritingTransport{
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

func (s *ussoSuite) TestGetGroupsReturnsNewSlice(c *qt.C) {
	lp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	rt := qthttptest.URLRewritingTransport{
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
	groups[0] = "test1@domain"
	groups, err = s.idp.GetGroups(s.idptest.Ctx, &store.Identity{
		ProviderID: store.MakeProviderIdentity("usso", "https://login.ubuntu.com/+id/test"),
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"test1", "test2"})
}

func (s *ussoSuite) TestWithDomain(c *qt.C) {
	s.idp = usso.NewIdentityProvider(usso.Params{
		Domain: "test1",
	})
	err := s.idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, idpPrefix))
	c.Assert(err, qt.Equals, nil)

	c.Assert(s.idp.Domain(), qt.Equals, "test1")

	ussoSrv := mockusso.NewServer()
	defer ussoSrv.Close()
	ussoSrv.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	ussoSrv.MockUSSO.SetLoginUser("test")

	id, err := s.idptest.DoInteractiveLogin(c, s.idp, idpPrefix+"/login", nil)
	c.Assert(err, qt.Equals, nil)
	candidtest.AssertEqualIdentity(c, id, &store.Identity{
		ProviderID: "usso:https://login.ubuntu.com/+id/test",
		Username:   "test@test1",
		Name:       "Test User",
		Email:      "test@example.com",
	})
}
