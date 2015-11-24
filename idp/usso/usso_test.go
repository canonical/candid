// Copyright 2015 Canonical Ltd.

package usso_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/usso"
	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/mockusso"
	"github.com/CanonicalLtd/blues-identity/params"
)

type ussoSuite struct {
	mockusso.Suite
	testing.IsolationSuite
	idp idp.IdentityProvider
}

var _ = gc.Suite(&ussoSuite{})

func (s *ussoSuite) SetUpSuite(c *gc.C) {
	s.IsolationSuite.SetUpSuite(c)
	s.Suite.SetUpSuite(c)
}

func (s *ussoSuite) TearDownSuite(c *gc.C) {
	s.Suite.TearDownSuite(c)
	s.IsolationSuite.TearDownSuite(c)
}

func (s *ussoSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	s.Suite.SetUpTest(c)
	s.idp = usso.IdentityProvider
}

func (s *ussoSuite) TearDownTest(c *gc.C) {
	s.Suite.TearDownTest(c)
	s.IsolationSuite.TearDownTest(c)
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
		URLPrefix: "https://idp.test",
	}
	t, err := s.idp.URL(tc, "1")
	c.Assert(err, gc.IsNil)
	u, err := url.Parse(t)
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
	b, err := bakery.NewService(bakery.NewServiceParams{})
	c.Assert(err, gc.IsNil)
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Bakery_:   b,
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
	u, err := s.idp.URL(tc, "2")
	c.Assert(err, gc.IsNil)
	resp, err := cl.Get(u)
	defer resp.Body.Close()
	tc.Request, err = http.NewRequest("GET", resp.Header.Get("Location"), nil)
	c.Assert(err, gc.IsNil)
	tc.Request.ParseForm()
	s.idp.Handle(tc)
	idptest.AssertLoginSuccess(c, tc, checkers.TimeBefore, &params.User{
		Username:   params.Username("test"),
		ExternalID: "https://login.ubuntu.com/+id/test",
		FullName:   "Test User", Email: "test@example.com",
	})
	c.Assert(tc.Response().Body.String(), gc.Equals, "login successful as user test\n")
}

func (s *ussoSuite) TestHandleSuccessNoExtensions(c *gc.C) {
	b, err := bakery.NewService(bakery.NewServiceParams{})
	c.Assert(err, gc.IsNil)
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Bakery_:   b,
	}
	err = tc.UpdateUser(&params.User{
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
	u, err := s.idp.URL(tc, "3")
	c.Assert(err, gc.IsNil)
	resp, err := cl.Get(u)
	defer resp.Body.Close()
	tc.Request, err = http.NewRequest("GET", resp.Header.Get("Location"), nil)
	c.Assert(err, gc.IsNil)
	tc.Request.ParseForm()
	s.idp.Handle(tc)
	idptest.AssertLoginSuccess(c, tc, checkers.TimeBefore, &params.User{
		ExternalID: "https://login.ubuntu.com/+id/test",
		Username:   params.Username("test"),
		FullName:   "Test User",
		Email:      "test@example.com",
	})
	c.Assert(tc.Response().Body.String(), gc.Equals, "login successful as user test\n")
}

func (s *ussoSuite) TestHandleNoExtensionsNotFound(c *gc.C) {
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
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
	u, err := s.idp.URL(tc, "4")
	c.Assert(err, gc.IsNil)
	resp, err := cl.Get(u)
	defer resp.Body.Close()
	tc.Request, err = http.NewRequest("GET", resp.Header.Get("Location"), nil)
	c.Assert(err, gc.IsNil)
	tc.Request.ParseForm()
	s.idp.Handle(tc)
	idptest.AssertLoginFailure(c, tc, `cannot get user details for "https://login.ubuntu.com/\+id/test": cannot find external id "https://login.ubuntu.com/\+id/test"`)
	err, _ = tc.LoginFailureCall()
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrForbidden)
}

func (s *ussoSuite) TestInteractiveLoginFromDifferentProvider(c *gc.C) {
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
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
	v.Set("openid.return_to", "https://idp.test/v1/idp/usso/callback")
	v.Set("openid.realm", "https://idp.test/v1/idp/usso/callback")
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
	s.idp.Handle(tc)
	idptest.AssertLoginFailure(c, tc, `.*rejecting login from https://login\.badplace\.com/\+openid`)
}
