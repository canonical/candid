// Copyright 2015 Canonical Ltd.

package usso_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/juju/idmclient/params"
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/usso"
	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/mockusso"
)

type ussoSuite struct {
	mockusso.Suite
	testing.IsolatedMgoSuite
	idp idp.IdentityProvider
}

var _ = gc.Suite(&ussoSuite{})

func (s *ussoSuite) SetUpSuite(c *gc.C) {
	s.IsolatedMgoSuite.SetUpSuite(c)
	s.Suite.SetUpSuite(c)
}

func (s *ussoSuite) TearDownSuite(c *gc.C) {
	s.Suite.TearDownSuite(c)
	s.IsolatedMgoSuite.TearDownSuite(c)
}

func (s *ussoSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	s.Suite.SetUpTest(c)
	s.idp = usso.IdentityProvider
}

func (s *ussoSuite) TearDownTest(c *gc.C) {
	s.Suite.TearDownTest(c)
	s.IsolatedMgoSuite.TearDownTest(c)
}

func (s *ussoSuite) TestConfig(c *gc.C) {
	configYaml := `
identity-providers:
 - type: usso
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(configYaml), &conf)
	c.Assert(err, gc.IsNil)
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
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: "https://idp.test",
	}
	c.Assert(s.idp.URL(tc, "1"), gc.Equals, "https://idp.test/login?waitid=1")
}

func (s *ussoSuite) TestRedirect(c *gc.C) {
	req, err := http.NewRequest("", "https://idp.test?waitid=1", nil)
	c.Assert(err, gc.Equals, nil)
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: "https://idp.test",
		Database_: s.Session.DB("test"),
		Request:   req,
	}
	tc.Request.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	c.Assert(rr.Code, gc.Equals, http.StatusFound)
	u, err := url.Parse(rr.Header().Get("Location"))
	c.Assert(err, gc.IsNil)
	c.Assert(u.Host, gc.Equals, "login.ubuntu.com")
	c.Assert(u.Path, gc.Equals, "/+openid")
	q := u.Query()
	c.Assert(q, jc.DeepEquals, url.Values{
		"openid.ns":                  []string{"http://specs.openid.net/auth/2.0"},
		"openid.claimed_id":          []string{"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.identity":            []string{"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.mode":                []string{"checkid_setup"},
		"openid.realm":               []string{"https://idp.test/callback"},
		"openid.return_to":           []string{"https://idp.test/callback?waitid=1"},
		"openid.ns.lp":               []string{"http://ns.launchpad.net/2007/openid-teams"},
		"openid.lp.query_membership": []string{"blues-development,charm-beta"},
		"openid.ns.sreg":             []string{"http://openid.net/extensions/sreg/1.1"},
		"openid.sreg.required":       []string{"email,fullname,nickname"},
	})
}

func (s *ussoSuite) TestHandleSuccess(c *gc.C) {
	db := s.Session.DB("test")
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: "https://idp.test",
		Bakery_:   bakery.New(bakery.BakeryParams{}),
		Database_: db,
	}
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.MockUSSO.SetLoginUser("test")
	cl := http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("no redirect")
		},
	}
	resp, err := cl.Get(s.ussoURL(c, "https://idp.test", db, "2"))
	defer resp.Body.Close()
	tc.Request, err = http.NewRequest("GET", resp.Header.Get("Location"), nil)
	c.Assert(err, gc.IsNil)
	tc.Request.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	idptest.AssertLoginSuccess(c, tc, "test")
	idptest.AssertUser(c, tc, &params.User{
		Username:   params.Username("test"),
		ExternalID: "https://login.ubuntu.com/+id/test",
		FullName:   "Test User", Email: "test@example.com",
	})
	c.Assert(rr.Body.String(), gc.Equals, "login successful as user test\n")
}

func (s *ussoSuite) TestHandleSuccessNoExtensions(c *gc.C) {
	db := s.Session.DB("test")
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: "https://idp.test",
		Bakery_:   bakery.New(bakery.BakeryParams{}),
		Database_: db,
	}
	err := tc.UpdateUser(&params.User{
		ExternalID: "https://login.ubuntu.com/+id/test",
		Username:   params.Username("test"),
		FullName:   "Test User",
		Email:      "test@example.com",
	})
	c.Assert(err, gc.IsNil)
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.MockUSSO.SetLoginUser("test")
	s.MockUSSO.ExcludeExtensions()
	cl := http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("no redirect")
		},
	}
	resp, err := cl.Get(s.ussoURL(c, "https://idp.test", db, "3"))
	defer resp.Body.Close()
	tc.Request, err = http.NewRequest("GET", resp.Header.Get("Location"), nil)
	c.Assert(err, gc.IsNil)
	tc.Request.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	idptest.AssertLoginSuccess(c, tc, "test")
	idptest.AssertUser(c, tc, &params.User{
		ExternalID: "https://login.ubuntu.com/+id/test",
		Username:   params.Username("test"),
		FullName:   "Test User",
		Email:      "test@example.com",
	})
	c.Assert(rr.Body.String(), gc.Equals, "login successful as user test\n")
}

func (s *ussoSuite) TestHandleNoExtensionsNotFound(c *gc.C) {
	db := s.Session.DB("test")
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: "https://idp.test",
		Database_: db,
	}
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.MockUSSO.SetLoginUser("test")
	s.MockUSSO.ExcludeExtensions()
	cl := http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("no redirect")
		},
	}
	resp, err := cl.Get(s.ussoURL(c, "https://idp.test", db, "4"))
	defer resp.Body.Close()
	tc.Request, err = http.NewRequest("GET", resp.Header.Get("Location"), nil)
	c.Assert(err, gc.IsNil)
	tc.Request.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	idptest.AssertLoginFailure(c, tc, `invalid user: username not specified`)
	err, _ = tc.LoginFailureCall()
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrForbidden)
}

func (s *ussoSuite) TestInteractiveLoginFromDifferentProvider(c *gc.C) {
	db := s.Session.DB("test")
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: "https://idp.test",
		Database_: db,
	}
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
	cl := http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("no redirect")
		},
	}
	resp, err := cl.Get(u.String())
	defer resp.Body.Close()
	tc.Request, err = http.NewRequest("GET", resp.Header.Get("Location"), nil)
	c.Assert(err, gc.IsNil)
	tc.Request.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	idptest.AssertLoginFailure(c, tc, `.*rejecting login from https://login\.badplace\.com/\+openid`)
}

func (s *ussoSuite) TestHandleUpdateUserError(c *gc.C) {
	db := s.Session.DB("test")
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: "https://idp.test",
		Bakery_:   bakery.New(bakery.BakeryParams{}),
		Database_: db,
	}
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test-",
		FullName: "Test User",
		Email:    "test@example.com",
	})
	s.MockUSSO.SetLoginUser("test")
	cl := http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("no redirect")
		},
	}
	resp, err := cl.Get(s.ussoURL(c, "https://idp.test", db, "5"))
	defer resp.Body.Close()
	tc.Request, err = http.NewRequest("GET", resp.Header.Get("Location"), nil)
	c.Assert(err, gc.IsNil)
	tc.Request.ParseForm()
	tc.UpdateUserError = errgo.New(`invalid username "test-"`)
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	idptest.AssertLoginFailure(c, tc, `invalid username "test-"`)
}

func (s *ussoSuite) ussoURL(c *gc.C, prefix string, db *mgo.Database, waitid string) string {
	tc := &idptest.TestContext{
		Context:   context.Background(),
		URLPrefix: prefix,
		Database_: db,
	}
	var err error
	tc.Request, err = http.NewRequest("", s.idp.URL(tc, waitid), nil)
	c.Assert(err, gc.Equals, nil)
	tc.Request.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(tc, rr, tc.Request)
	c.Assert(rr.Code, gc.Equals, http.StatusFound)
	return rr.Header().Get("Location")
}
