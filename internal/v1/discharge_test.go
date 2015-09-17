// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/garyburd/go-oauth/oauth"
	"github.com/juju/httprequest"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/goose.v1/testing/httpsuite"
	"gopkg.in/goose.v1/testservices/identityservice"
	"gopkg.in/juju/environschema.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon-bakery.v1/httpbakery/form"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/idtesting/mockusso"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

type dischargeSuite struct {
	apiSuite
	mockusso.Suite
	httpsuite.HTTPSuite
	locator  *bakery.PublicKeyRing
	netSrv   *httptest.Server
	keystone *identityservice.UserPass
}

var _ = gc.Suite(&dischargeSuite{})

func (s *dischargeSuite) SetUpSuite(c *gc.C) {
	s.Suite.SetUpSuite(c)
	s.HTTPSuite.SetUpSuite(c)
	s.apiSuite.SetUpSuite(c)
}

func (s *dischargeSuite) TearDownSuite(c *gc.C) {
	s.HTTPSuite.TearDownSuite(c)
	s.Suite.TearDownSuite(c)
	s.apiSuite.TearDownSuite(c)
}

func (s *dischargeSuite) SetUpTest(c *gc.C) {
	s.Suite.SetUpTest(c)
	s.HTTPSuite.SetUpTest(c)
	s.keystone = identityservice.NewUserPass()
	s.keystone.SetupHTTP(s.Mux)
	s.apiSuite.idps = []idp.IdentityProvider{
		idp.UbuntuSSOIdentityProvider,
		idp.UbuntuSSOOAuthIdentityProvider,
		idp.AgentIdentityProvider,
		idp.KeystoneUserpassIdentityProvider(
			&idp.KeystoneParams{
				Name: "form",
				URL:  s.Server.URL,
			},
		),
	}
	s.apiSuite.SetUpTest(c)
	s.locator = bakery.NewPublicKeyRing()
	s.netSrv = httptest.NewServer(s.srv)
	s.locator.AddPublicKeyForLocation(s.netSrv.URL, true, &s.keyPair.Public)
}

func (s *dischargeSuite) TearDownTest(c *gc.C) {
	s.netSrv.Close()
	s.HTTPSuite.TearDownTest(c)
	s.apiSuite.TearDownTest(c)
	s.Suite.TearDownTest(c)
}

func (s *dischargeSuite) TestDischargeWhenLoggedIn(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	uuid := s.createUser(c, &params.User{
		Username:   "test-user",
		ExternalID: "http://example.com/test-user",
		Email:      "test-user@example.com",
		FullName:   "Test User III",
		IDPGroups: []string{
			"test",
			"test2",
		},
	})
	// Create the service which will issue the third party caveat.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := svc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  s.netSrv.URL,
		Condition: "is-authenticated-user",
	}})
	c.Assert(err, gc.IsNil)
	idm, err := store.Service.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", "test-user"),
	})
	c.Assert(err, gc.IsNil)
	u, err := url.Parse(s.netSrv.URL)
	c.Assert(err, gc.IsNil)
	bakeryClient := httpbakery.NewClient()
	err = httpbakery.SetCookie(bakeryClient.Client.Jar, u, macaroon.Slice{idm})
	c.Assert(err, gc.IsNil)
	ms, err := bakeryClient.DischargeAll(m)
	c.Assert(err, gc.IsNil)
	d := checkers.InferDeclared(ms)
	err = svc.Check(ms, checkers.New(d, checkers.TimeBefore))
	c.Assert(err, gc.IsNil)
	c.Assert(d, jc.DeepEquals, checkers.Declared{
		"uuid":     uuid,
		"username": "test-user",
	})
}

// This test is not sending the bakery protocol version so it will use the default
// one and return a 407.
func (s *dischargeSuite) TestDischargeStatusProxyAuthRequiredResponse(c *gc.C) {
	// Create the service which will issue the third party caveat.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := svc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  s.netSrv.URL,
		Condition: "is-authenticated-user",
	}})

	cav := m.Caveats()[0]
	resp, err := http.PostForm(s.netSrv.URL+"/discharge", url.Values{
		"id":       {cav.Id},
		"location": {cav.Location},
	})
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()

	c.Assert(resp.StatusCode, gc.Equals, http.StatusProxyAuthRequired)
}

// This test is using the bakery protocol version at value 1 to be able to return a 401
// instead of a 407
func (s *dischargeSuite) TestDischargeStatusUnauthorizedResponse(c *gc.C) {
	// Create the service which will issue the third party caveat.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := svc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  s.netSrv.URL,
		Condition: "is-authenticated-user",
	}})

	cav := m.Caveats()[0]
	values := url.Values{
		"id":       {cav.Id},
		"location": {cav.Location},
	}

	req, err := http.NewRequest("POST", s.netSrv.URL+"/discharge", strings.NewReader(values.Encode()))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Bakery-Protocol-Version", "1")
	resp, err := http.DefaultClient.Do(req)
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()

	c.Assert(resp.StatusCode, gc.Equals, http.StatusUnauthorized)
	c.Assert(resp.Header.Get("WWW-Authenticate"), gc.Equals, "Macaroon")
}

func (s *dischargeSuite) TestDischargeMemberOf(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	s.createUser(c, &params.User{
		Username:   "test-user",
		ExternalID: "http://example.com/test-user",
		Email:      "test-user@example.com",
		FullName:   "Test User III",
		IDPGroups: []string{
			"test",
			"test2",
		},
	})
	// Create the service which will issue the third party caveat.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)

	tests := []struct {
		about          string
		createMacaroon func() (*macaroon.Macaroon, error)
		expectError    string
		expectDeclared checkers.Declared
	}{{
		about: "test membership in single group - matches",
		createMacaroon: func() (*macaroon.Macaroon, error) {
			return svc.NewMacaroon("", nil, []checkers.Caveat{{
				Location:  s.netSrv.URL,
				Condition: "is-member-of test",
			}})
		},
		expectDeclared: checkers.Declared{},
	}, {
		about: "test membership in a set of groups",
		createMacaroon: func() (*macaroon.Macaroon, error) {
			return svc.NewMacaroon("", nil, []checkers.Caveat{{
				Location:  s.netSrv.URL,
				Condition: "is-member-of test test2",
			}})
		},
		expectDeclared: checkers.Declared{},
	}, {
		about: "test membership in single group - no match",
		createMacaroon: func() (*macaroon.Macaroon, error) {
			return svc.NewMacaroon("", nil, []checkers.Caveat{{
				Location:  s.netSrv.URL,
				Condition: "is-member-of test1",
			}})
		},
		expectError: "third party refused discharge: cannot discharge: user is not a member of required groups",
	}, {
		about: "test membership in a set of groups - one group matches",
		createMacaroon: func() (*macaroon.Macaroon, error) {
			return svc.NewMacaroon("", nil, []checkers.Caveat{{
				Location:  s.netSrv.URL,
				Condition: "is-member-of test test3 test4",
			}})
		},
		expectDeclared: checkers.Declared{},
	}, {
		about: "test membership in a set of groups fail - no match",
		createMacaroon: func() (*macaroon.Macaroon, error) {
			return svc.NewMacaroon("", nil, []checkers.Caveat{{
				Location:  s.netSrv.URL,
				Condition: "is-member-of test1 test3",
			}})
		},
		expectError: "third party refused discharge: cannot discharge: user is not a member of required groups",
	},
	}

	for _, test := range tests {
		c.Logf("test: %q", test.about)
		m, err := test.createMacaroon()
		c.Assert(err, gc.IsNil)
		idm, err := store.Service.NewMacaroon("", nil, []checkers.Caveat{
			checkers.DeclaredCaveat("username", "test-user"),
		})
		c.Assert(err, gc.IsNil)
		u, err := url.Parse(s.netSrv.URL)
		c.Assert(err, gc.IsNil)
		bakeryClient := httpbakery.NewClient()
		err = httpbakery.SetCookie(bakeryClient.Client.Jar, u, macaroon.Slice{idm})
		c.Assert(err, gc.IsNil)
		ms, err := bakeryClient.DischargeAll(m)
		if test.expectError != "" {
			c.Assert(errgo.Cause(err), gc.ErrorMatches, test.expectError)
		} else {
			c.Assert(err, gc.IsNil)
			d := checkers.InferDeclared(ms)
			err = svc.Check(ms, checkers.New(d, checkers.TimeBefore))
			c.Assert(err, gc.IsNil)
			c.Assert(d, jc.DeepEquals, test.expectDeclared)
		}
	}
}

func (s *dischargeSuite) TestAdminDischarge(c *gc.C) {
	s.createUser(c, &params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
		Email:      "jbloggs@example.com",
		FullName:   "Joe Bloggs",
		IDPGroups: []string{
			"test",
		},
	})
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)
	tests := []struct {
		about     string
		m         *macaroon.Macaroon
		modifier  *requestModifier
		expectErr string
	}{{
		about: "discharge macaroon",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  s.netSrv.URL,
			Condition: "is-authenticated-user",
		}}),
		modifier: &requestModifier{
			f: func(r *http.Request) {
				r.SetBasicAuth(adminUsername, adminPassword)
				r.URL.RawQuery += "&discharge-for-user=jbloggs"
			},
		},
		expectErr: "",
	}, {
		about: "no discharge user",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  s.netSrv.URL,
			Condition: "is-authenticated-user",
		}}),
		modifier: &requestModifier{
			f: func(r *http.Request) {
				r.SetBasicAuth(adminUsername, adminPassword)
			},
		},
		expectErr: ".*cannot discharge: username not specified",
	}, {
		about: "no authentication",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  s.netSrv.URL,
			Condition: "is-authenticated-user",
		}}),
		modifier: &requestModifier{
			f: func(r *http.Request) {
				r.URL.RawQuery += "&discharge-for-user=jbloggs"
			},
		},
		expectErr: `cannot get discharge from "[^"]*": cannot start interactive session: interaction required but not possible`,
	}, {
		about: "unsupported user",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  s.netSrv.URL,
			Condition: "is-authenticated-user",
		}}),
		modifier: &requestModifier{
			f: func(r *http.Request) {
				r.SetBasicAuth(adminUsername, adminPassword)
				r.URL.RawQuery += "&discharge-for-user=jbloggs2"
			},
		},
		expectErr: `.*cannot discharge: user \"jbloggs2\" not found: not found`,
	}, {
		about: "unsupported condition",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  s.netSrv.URL,
			Condition: "is-authenticated-group",
		}}),
		modifier: &requestModifier{
			f: func(r *http.Request) {
				r.SetBasicAuth(adminUsername, adminPassword)
				r.URL.RawQuery += "&discharge-for-user=jbloggs"
			},
		},
		expectErr: `.*caveat not recognized`,
	}, {
		about: "bad credentials",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  s.netSrv.URL,
			Condition: "is-authenticated-user",
		}}),
		modifier: &requestModifier{
			f: func(r *http.Request) {
				r.SetBasicAuth("not-admin-username", adminPassword)
				r.URL.RawQuery += "&discharge-for-user=jbloggs2"
			},
		},
		expectErr: `.*third party refused discharge: cannot discharge: unauthorized: invalid credentials`,
	}}
	for i, test := range tests {
		c.Logf("test %d. %s", i, test.about)
		client := httpbakery.NewClient()
		if test.modifier != nil {
			test.modifier.transport = client.Client.Transport
			client.Client.Transport = test.modifier
		}
		ms, err := client.DischargeAll(test.m)
		if test.expectErr != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErr)
			continue
		}
		c.Assert(err, gc.IsNil)
		d := checkers.InferDeclared(ms)
		err = svc.Check(ms, checkers.New(
			d,
			checkers.TimeBefore,
		))
		c.Assert(err, gc.IsNil)
	}
}

func (s *dischargeSuite) TestDischargeWithOpenID(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "test",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
		Groups:   []string{"test1", "test2"},
	})
	s.MockUSSO.SetLoginUser("test")
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)
	client := httpbakery.NewClient()
	client.Client.Transport = transport{
		prefix: location,
		srv:    s.srv,
		rt:     http.DefaultTransport,
	}
	client.VisitWebPage = s.doVisit(c)
	m := newMacaroon(c, svc, []checkers.Caveat{{
		Location:  s.netSrv.URL,
		Condition: "is-authenticated-user",
	}})
	ms, err := client.DischargeAll(m)
	c.Assert(err, gc.IsNil)
	d := checkers.InferDeclared(ms)
	err = svc.Check(ms, checkers.New(
		d,
		checkers.TimeBefore,
	))
	c.Assert(err, gc.IsNil)
	id, err := store.GetIdentity(params.Username("test"))
	c.Assert(err, gc.IsNil)
	id.UUID = ""
	c.Assert(id, jc.DeepEquals, &mongodoc.Identity{
		ExternalID: "https://login.ubuntu.com/+id/test",
		Username:   "test",
		FullName:   "Test User",
		Email:      "test@example.com",
		Groups:     []string{"test1", "test2"},
	})
}

func (s *dischargeSuite) doVisit(c *gc.C) func(*url.URL) error {
	return func(u *url.URL) error {
		c.Logf("visiting %s", u)
		client := &http.Client{
			Transport: transport{
				prefix: location,
				srv:    s.srv,
				rt:     http.DefaultTransport,
			},
		}
		resp, err := client.Get(u.String())
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			data, _ := ioutil.ReadAll(resp.Body)
			c.Logf("Body: %s", data)
			return fmt.Errorf("bad status %q", resp.Status)
		}
		return nil
	}
}

func (s *dischargeSuite) TestDischargeWithOAuth(c *gc.C) {
	s.PatchValue(&http.DefaultTransport, transport{
		prefix: location,
		srv:    s.srv,
		rt:     http.DefaultTransport,
	})
	uuid := s.createUser(c, &params.User{
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
	// Create the service which will issue the third party caveat.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := svc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  s.netSrv.URL,
		Condition: "is-authenticated-user",
	}})
	c.Assert(err, gc.IsNil)
	bakeryClient := httpbakery.NewClient()
	bakeryClient.VisitWebPage = oauthVisit(c, client, goodToken)
	ms, err := bakeryClient.DischargeAll(m)
	c.Assert(err, gc.IsNil)
	d := checkers.InferDeclared(ms)
	err = svc.Check(ms, checkers.New(d, checkers.TimeBefore))
	c.Assert(err, gc.IsNil)
	c.Assert(d, jc.DeepEquals, checkers.Declared{
		"uuid":     uuid,
		"username": "test",
	})
}

func (s *dischargeSuite) TestDischargeWithOAuthBadToken(c *gc.C) {
	s.PatchValue(&http.DefaultTransport, transport{
		prefix: location,
		srv:    s.srv,
		rt:     http.DefaultTransport,
	})
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
	// Create the service which will issue the third party caveat.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := svc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  s.netSrv.URL,
		Condition: "is-authenticated-user",
	}})
	c.Assert(err, gc.IsNil)
	bakeryClient := httpbakery.NewClient()
	bakeryClient.VisitWebPage = oauthVisit(c, client, badToken)
	_, err = bakeryClient.DischargeAll(m)
	c.Assert(err, gc.ErrorMatches, `cannot get discharge from ".*": cannot start interactive session: invalid OAuth credentials`)
}

func noVisit(*url.URL) error {
	return errors.New("unexpected call to visit")
}

// oauthVisit returns a visit function that will sign a response to the return_to url
// with a the oauth credentials provided.
func oauthVisit(c *gc.C, client *oauth.Client, token *oauth.Credentials) func(*url.URL) error {
	return func(u *url.URL) error {
		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var loginMethods params.LoginMethods
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		err = json.Unmarshal(body, &loginMethods)
		if err != nil {
			return err
		}
		uOAuth, err := url.Parse(loginMethods.UbuntuSSOOAuth)
		if err != nil {
			return err
		}
		q := uOAuth.Query()
		uOAuth.RawQuery = ""
		c.Logf("OAUTH Visiting %s", loginMethods.UbuntuSSOOAuth)
		resp, err = client.Get(nil, token, uOAuth.String(), q)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		c.Logf("Status: %s", resp.Status)
		var perr params.Error
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		err = json.Unmarshal(body, &perr)
		if err != nil {
			return err
		}
		return &perr
	}
}

var never = bakery.FirstPartyCheckerFunc(func(string) error {
	return errors.New("unexpected first party caveat")
})

var always = bakery.FirstPartyCheckerFunc(func(string) error {
	return nil
})

// requestModifier implements an http RoundTripper
// that modifies any requests using the given function
// before calling the transport RoundTripper.
type requestModifier struct {
	transport http.RoundTripper
	f         func(*http.Request)
}

func (m *requestModifier) RoundTrip(r *http.Request) (*http.Response, error) {
	m.f(r)
	if m.transport == nil {
		return http.DefaultTransport.RoundTrip(r)
	} else {
		return m.transport.RoundTrip(r)
	}
}

func newMacaroon(c *gc.C, svc *bakery.Service, cav []checkers.Caveat) *macaroon.Macaroon {
	m, err := svc.NewMacaroon("", nil, cav)
	c.Assert(err, gc.IsNil)
	return m
}

var client = &oauth.Client{
	Credentials: oauth.Credentials{
		Token:  "1234",
		Secret: "secret1",
	},
	SignatureMethod: oauth.HMACSHA1,
}

var goodToken = &oauth.Credentials{
	Token:  "test-token",
	Secret: "secret2",
}

var badToken = &oauth.Credentials{
	Token:  "bad-token",
	Secret: "bad-secret2",
}

func (s *dischargeSuite) TestDischargeWithAgentLogin(c *gc.C) {
	s.PatchValue(&http.DefaultTransport, transport{
		prefix: location,
		srv:    s.srv,
		rt:     http.DefaultTransport,
	})
	keys, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	uuid := s.createIdentity(c, &mongodoc.Identity{
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
	// Create the service which will issue the third party caveat.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := svc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  s.netSrv.URL,
		Condition: "is-authenticated-user",
	}})
	c.Assert(err, gc.IsNil)
	bakeryClient := httpbakery.NewClient()
	bakeryClient.VisitWebPage = agentVisit(c, bakeryClient, "test", &keys.Public)
	bakeryClient.Key = keys
	ms, err := bakeryClient.DischargeAll(m)
	c.Assert(err, gc.IsNil)
	d := checkers.InferDeclared(ms)
	err = svc.Check(ms, checkers.New(d, checkers.TimeBefore))
	c.Assert(err, gc.IsNil)
	c.Assert(d, jc.DeepEquals, checkers.Declared{
		"uuid":     uuid,
		"username": "test",
	})
}

func (s *dischargeSuite) TestDischargeLegacyLocation(c *gc.C) {
	s.createUser(c, &params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
		Email:      "jbloggs@example.com",
		FullName:   "Joe Bloggs",
		IDPGroups: []string{
			"test",
		},
	})
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)
	client := httpbakery.NewClient()
	client.Client.Transport = &requestModifier{
		f: func(r *http.Request) {
			r.SetBasicAuth(adminUsername, adminPassword)
			r.URL.RawQuery += "&discharge-for-user=jbloggs"
		},
		transport: client.Client.Transport,
	}
	ms, err := client.DischargeAll(newMacaroon(c, svc, []checkers.Caveat{{
		Location:  s.netSrv.URL + "/v1/discharger",
		Condition: "is-authenticated-user",
	}}))
	c.Assert(err, gc.IsNil)
	d := checkers.InferDeclared(ms)
	err = svc.Check(ms, checkers.New(
		d,
		checkers.TimeBefore,
	))
	c.Assert(err, gc.IsNil)
}

func (s *dischargeSuite) TestPublicKeyLegacyLocation(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      s.srv,
		URL:          apiURL("discharger/publickey"),
		ExpectStatus: http.StatusOK,
		ExpectBody: map[string]*bakery.PublicKey{
			"PublicKey": &s.keyPair.Public,
		},
	})
}

func (s *dischargeSuite) TestPublicKey(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      s.srv,
		URL:          "/publickey",
		ExpectStatus: http.StatusOK,
		ExpectBody: map[string]*bakery.PublicKey{
			"PublicKey": &s.keyPair.Public,
		},
	})
}

func agentVisit(c *gc.C, client *httpbakery.Client, username string, pk *bakery.PublicKey) func(u *url.URL) error {
	return func(u *url.URL) error {
		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var loginMethods params.LoginMethods
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		err = json.Unmarshal(body, &loginMethods)
		if err != nil {
			return err
		}
		var p params.AgentLogin
		p.Username = params.Username(username)
		p.PublicKey = pk
		body, err = json.Marshal(p)
		if err != nil {
			return err
		}
		req, err = http.NewRequest("POST", loginMethods.Agent, nil)
		req.Header.Set("Content-Type", "application/json")
		if err != nil {
			return err
		}
		resp, err = client.DoWithBody(req, bytes.NewReader(body))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		c.Logf("Status: %s", resp.Status)
		var perr params.Error
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		err = json.Unmarshal(body, &perr)
		if err != nil {
			return err
		}
		return &perr
	}
}

func (s *dischargeSuite) TestKeystoneSchema(c *gc.C) {
	s.Mux.Handle("/tenants", http.HandlerFunc(s.handleTenants))
	s.PatchValue(&http.DefaultTransport, transport{
		prefix: location,
		srv:    s.srv,
		rt:     http.DefaultTransport,
	})
	userInfo := s.keystone.AddUser("ksuser", "kspass", "test_project")
	uuid := s.createIdentity(c, &mongodoc.Identity{
		Username:   "ksuser",
		ExternalID: userInfo.Id,
	})
	// Create the service which will issue the third party caveat.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := svc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  s.netSrv.URL,
		Condition: "is-authenticated-user",
	}})
	c.Assert(err, gc.IsNil)
	bakeryClient := httpbakery.NewClient()
	form.SetUpAuth(bakeryClient, &keystoneFormFiller{
		username: "ksuser",
		password: "kspass",
	})
	ms, err := bakeryClient.DischargeAll(m)
	c.Assert(err, gc.IsNil)
	d := checkers.InferDeclared(ms)
	err = svc.Check(ms, checkers.New(d, checkers.TimeBefore))
	c.Assert(err, gc.IsNil)
	c.Assert(d, jc.DeepEquals, checkers.Declared{
		"uuid":     uuid,
		"username": "ksuser",
	})
}

type tenant struct {
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	ID          string `json:"id"`
	Name        string `json:"name"`
}

type tenantsResponse struct {
	Tenants []tenant `json:"tenants"`
}

func (s *dischargeSuite) handleTenants(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Auth-Token")
	_, err := s.keystone.FindUser(token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
	}
	httprequest.WriteJSON(w, http.StatusOK, tenantsResponse{
		Tenants: []tenant{{
			Description: "test_project description",
			Enabled:     true,
			ID:          "test_project_id",
			Name:        "test_project",
		}},
	})
}

type keystoneFormFiller struct {
	username, password string
}

func (h keystoneFormFiller) Fill(s environschema.Fields) (map[string]interface{}, error) {
	if _, ok := s["username"]; !ok {
		return nil, errgo.New("schema has no username")
	}
	if _, ok := s["password"]; !ok {
		return nil, errgo.New("schema has no password")
	}
	return map[string]interface{}{
		"username": h.username,
		"password": h.password,
	}, nil
}
