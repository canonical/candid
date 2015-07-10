// Copyright 2015 Canonical Ltd.

package v1_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/garyburd/go-oauth/oauth"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/internal/idtesting/mockusso"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

type loginSuite struct {
	apiSuite
	mockusso.Suite
	netSrv *httptest.Server
}

var _ = gc.Suite(&loginSuite{})

func (s *loginSuite) SetUpSuite(c *gc.C) {
	s.Suite.SetUpSuite(c)
	s.apiSuite.SetUpSuite(c)
}

func (s *loginSuite) TearDownSuite(c *gc.C) {
	s.Suite.TearDownSuite(c)
	s.apiSuite.TearDownSuite(c)
}

func (s *loginSuite) SetUpTest(c *gc.C) {
	s.Suite.SetUpTest(c)
	s.apiSuite.SetUpTest(c)
	s.netSrv = httptest.NewServer(s.srv)
}

func (s *loginSuite) TearDownTest(c *gc.C) {
	s.netSrv.Close()
	s.apiSuite.TearDownTest(c)
	s.Suite.TearDownTest(c)
}

func (s *loginSuite) TestInteractiveLogin(c *gc.C) {
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
		Groups:   []string{"test1", "test2"},
	})
	s.MockUSSO.SetLoginUser("test")
	client := &http.Client{
		Transport: transport{
			prefix: location,
			srv:    s.srv,
			rt:     http.DefaultTransport,
		},
	}
	resp, err := client.Get(location + "/v1/login")
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	s.assertMacaroon(c, resp, "test")
}

func (s *loginSuite) TestInteractiveLoginFromDifferentProvider(c *gc.C) {
	mockUSSO := mockusso.New("https://login.badplace.com")
	s.PatchValue(&http.DefaultTransport, transport{
		prefix: "https://login.badplace.com",
		srv:    mockUSSO,
		rt:     http.DefaultTransport,
	})
	mockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
		Groups:   []string{"test1", "test2"},
	})
	mockUSSO.SetLoginUser("test")
	client := &http.Client{
		Transport: transport{
			prefix: location,
			srv:    s.srv,
			rt:     http.DefaultTransport,
		},
	}
	v := url.Values{}
	v.Set("openid.ns", "http://specs.openid.net/auth/2.0")
	v.Set("openid.mode", "checkid_setup")
	v.Set("openid.claimed_id", "https://login.badplace.com")
	v.Set("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
	v.Set("openid.return_to", location+"/v1/idp/usso/callback")
	v.Set("openid.realm", location+"/v1/idp/usso/callback")
	u := &url.URL{
		Scheme:   "https",
		Host:     "login.badplace.com",
		Path:     "/+openid",
		RawQuery: v.Encode(),
	}
	resp, err := client.Get(u.String())
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusForbidden)
	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, gc.IsNil)
	var perr params.Error
	err = json.Unmarshal(body, &perr)
	c.Assert(err, gc.IsNil)
	c.Assert(perr.Code, gc.Equals, params.ErrForbidden)
	c.Assert(&perr, gc.ErrorMatches, `.*rejecting login from https://login\.badplace\.com/\+openid`)
}

func (s *loginSuite) TestOAuthLogin(c *gc.C) {
	s.createUser(c, &params.User{
		Username:   "test",
		ExternalID: "https://login.ubuntu.com/+id/1234",
		Email:      "test@example.com",
		FullName:   "Test User",
		IDPGroups: []string{
			"test",
		},
	})
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "1234",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
		Groups: []string{
			"test",
		},
		ConsumerSecret: "secret1",
		TokenKey:       "test-token",
		TokenSecret:    "secret2",
	})
	client := new(http.Client)
	client.Transport = transport{
		prefix: location,
		srv:    s.srv,
		rt:     http.DefaultTransport,
	}
	req, err := http.NewRequest("GET", location+"/v1/login", nil)
	c.Assert(err, gc.IsNil)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	c.Assert(resp.Header.Get("Content-Type"), gc.Equals, "application/json")
	data, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, gc.IsNil)
	var loginMethods params.LoginMethods
	err = json.Unmarshal(data, &loginMethods)
	c.Assert(err, gc.IsNil)
	oc := &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  "1234",
			Secret: "secret1",
		},
		SignatureMethod: oauth.HMACSHA1,
	}
	resp, err = oc.Get(
		client,
		&oauth.Credentials{
			Token:  "test-token",
			Secret: "secret2",
		},
		loginMethods.UbuntuSSOOAuth,
		nil,
	)
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()
	s.assertMacaroon(c, resp, "test")
}

func (s *loginSuite) TestAgentLogin(c *gc.C) {
	keys, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.createIdentity(c, &mongodoc.Identity{
		Username: "test",
		Email:    "test@example.com",
		FullName: "Test User",
		Groups: []string{
			"test",
		},
		Owner: "admin",
		PublicKeys: []mongodoc.PublicKey{{
			Key: keys.Public.Key[:],
		}},
	})
	client := httpbakery.NewClient()
	client.Client.Transport = transport{
		prefix: location,
		srv:    s.srv,
		rt:     http.DefaultTransport,
	}
	client.Key = keys
	req, err := http.NewRequest("GET", location+"/v1/login", nil)
	c.Assert(err, gc.IsNil)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	c.Assert(resp.Header.Get("Content-Type"), gc.Equals, "application/json")
	data, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, gc.IsNil)
	var loginMethods params.LoginMethods
	err = json.Unmarshal(data, &loginMethods)
	c.Assert(err, gc.IsNil)
	var p params.AgentLogin
	p.Username = "test"
	p.PublicKey = &keys.Public
	data, err = json.Marshal(p)
	c.Assert(err, gc.IsNil)
	req, err = http.NewRequest("POST", loginMethods.Agent, nil)
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.DoWithBody(req, bytes.NewReader(data))
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()
	data, err = ioutil.ReadAll(resp.Body)
	c.Assert(err, gc.IsNil)
	var al params.AgentLogin
	err = json.Unmarshal(data, &al)
	c.Assert(err, gc.IsNil)
	c.Assert(al, jc.DeepEquals, p)
	s.assertMacaroon(c, resp, "test")
}

func (s *loginSuite) assertMacaroon(c *gc.C, resp *http.Response, userId string) {
	var ms macaroon.Slice
	for _, cookie := range resp.Cookies() {
		if strings.HasPrefix(cookie.Name, "macaroon-") {
			data, err := base64.StdEncoding.DecodeString(cookie.Value)
			c.Assert(err, gc.IsNil)
			err = json.Unmarshal(data, &ms)
			c.Assert(err, gc.IsNil)
			break
		}
	}
	c.Assert(ms, gc.Not(gc.HasLen), 0)
	cavs := ms[0].Caveats()
	var found bool
	for _, cav := range cavs {
		if strings.HasPrefix(cav.Id, "declared username") {
			found = true
			un := strings.TrimPrefix(cav.Id, "declared username ")
			c.Assert(un, gc.Equals, userId)
		}
	}
	c.Assert(found, gc.Equals, true, gc.Commentf("no username  caveat"))
}
