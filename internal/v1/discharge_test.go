// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/juju/idmclient/params"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon-bakery.v1/httpbakery/agent"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/idp"
	agentidp "github.com/CanonicalLtd/blues-identity/idp/agent"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/test"
	"github.com/CanonicalLtd/blues-identity/internal/v1"
)

type dischargeSuite struct {
	idptest.DischargeSuite
	user *params.User
}

var _ = gc.Suite(&dischargeSuite{})

func (s *dischargeSuite) SetUpTest(c *gc.C) {
	s.IDPs = []idp.IdentityProvider{
		test.IdentityProvider,
		agentidp.IdentityProvider,
	}
	s.DischargeSuite.SetUpTest(c)
	s.user = &params.User{
		Username:   "test",
		ExternalID: "https://example.com/+id/test",
		FullName:   "Test User",
		Email:      "test@example.com",
		IDPGroups:  []string{"test1", "test2"},
	}
}

func (s *dischargeSuite) TestInteractiveDischarge(c *gc.C) {
	visitor := &test.WebPageVisitor{
		Client: s.HTTPRequestClient,
		User:   s.user,
	}
	s.AssertDischarge(c, visitor.Interactive, checkers.New(
		checkers.TimeBefore,
	))
}

func (s *dischargeSuite) TestNonInteractiveDischarge(c *gc.C) {
	visitor := &test.WebPageVisitor{
		Client: s.HTTPRequestClient,
		User:   s.user,
	}
	s.AssertDischarge(c, visitor.NonInteractive, checkers.New(
		checkers.TimeBefore,
	))
}

func (s *dischargeSuite) TestDischargeUsernameLookup(c *gc.C) {
	err := s.IDMClient.SetUser(&params.SetUserRequest{
		Username: s.user.Username,
		User:     *s.user,
	})
	c.Assert(err, gc.IsNil)
	visitor := &test.WebPageVisitor{
		Client: s.HTTPRequestClient,
		User: &params.User{
			Username: s.user.Username,
		},
	}
	s.AssertDischarge(c, visitor.Interactive, checkers.New(
		checkers.TimeBefore,
	))
}

func (s *dischargeSuite) TestDischargeExternalIDLookup(c *gc.C) {
	err := s.IDMClient.SetUser(&params.SetUserRequest{
		Username: s.user.Username,
		User:     *s.user,
	})
	c.Assert(err, gc.IsNil)
	visitor := &test.WebPageVisitor{
		Client: s.HTTPRequestClient,
		User: &params.User{
			ExternalID: s.user.ExternalID,
		},
	}
	s.AssertDischarge(c, visitor.Interactive, checkers.New(
		checkers.TimeBefore,
	))
}

func (s *dischargeSuite) TestDischargeWhenLoggedIn(c *gc.C) {
	visitor := &test.WebPageVisitor{
		Client: s.HTTPRequestClient,
		User:   s.user,
	}
	s.AssertDischarge(c, visitor.Interactive, checkers.New(
		checkers.TimeBefore,
	))
	s.AssertDischarge(c, noVisit, checkers.New(
		checkers.TimeBefore,
	))

	// Check that we cannot do the same when we're
	// making the requests from a different origin.
	s.AssertDischarge(c, noVisit, checkers.New(
		checkers.TimeBefore,
	))
}

func (s *dischargeSuite) TestWaitReturnsDischargeToken(c *gc.C) {
	visitor := &test.WebPageVisitor{
		Client: s.HTTPRequestClient,
		User:   s.user,
	}
	transport := &responseBodyRecordingTransport{
		c:         c,
		transport: s.BakeryClient.Transport,
	}
	s.BakeryClient.Transport = transport
	s.AssertDischarge(c, visitor.Interactive, checkers.New(
		checkers.TimeBefore,
	))
	u, _ := url.Parse(idptest.DischargeLocation)
	mss := cookiesToMacaroons(s.BakeryClient.Jar.Cookies(u))
	c.Assert(mss, gc.HasLen, 1)
	c.Assert(mss[0], gc.HasLen, 1)

	dischargeCount := 0
	// Check that the responses to /discharge also included discharge tokens
	// the same as the cookie.
	for _, resp := range transport.responses {
		if !strings.HasSuffix(resp.url.Path, "/wait") {
			c.Logf("ignoring %v (path %s)", resp.url, resp.url.Path)
			continue
		}
		dischargeCount++
		var wresp v1.WaitResponse
		err := json.Unmarshal(resp.body, &wresp)
		c.Assert(err, gc.IsNil)
		c.Assert(wresp.DischargeToken, gc.HasLen, 1)
		c.Assert(wresp.DischargeToken[0].Signature(), gc.DeepEquals, mss[0][0].Signature())
	}
	c.Assert(dischargeCount, gc.Not(gc.Equals), 0)
}

// cookiesToMacaroons returns a slice of any macaroons found
// in the given slice of cookies.
func cookiesToMacaroons(cookies []*http.Cookie) []macaroon.Slice {
	var mss []macaroon.Slice
	for _, cookie := range cookies {
		if !strings.HasPrefix(cookie.Name, "macaroon-") {
			continue
		}
		ms, err := decodeMacaroonSlice(cookie.Value)
		if err != nil {
			continue
		}
		mss = append(mss, ms)
	}
	return mss
}

// decodeMacaroonSlice decodes a base64-JSON-encoded slice of macaroons from
// the given string.
func decodeMacaroonSlice(value string) (macaroon.Slice, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot base64-decode macaroons")
	}
	var ms macaroon.Slice
	if err := json.Unmarshal(data, &ms); err != nil {
		return nil, errgo.NoteMask(err, "cannot unmarshal macaroons")
	}
	return ms, nil
}

func isVerificationError(err error) bool {
	_, ok := err.(*bakery.VerificationError)
	return ok
}

type responseBody struct {
	url    *url.URL
	body   []byte
	header http.Header
}

type responseBodyRecordingTransport struct {
	c         *gc.C
	transport http.RoundTripper
	responses []responseBody
}

func (t *responseBodyRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	io.Copy(&buf, resp.Body)
	resp.Body = ioutil.NopCloser(&buf)
	if resp.StatusCode == 200 {
		t.responses = append(t.responses, responseBody{
			url:  req.URL,
			body: buf.Bytes(),
		})
	}
	return resp, nil
}

func (s *dischargeSuite) TestDischargeFromDifferentOriginWhenLoggedIn(c *gc.C) {
	visitor := &test.WebPageVisitor{
		Client: s.HTTPRequestClient,
		User:   s.user,
	}
	s.AssertDischarge(c, visitor.Interactive, checkers.New(
		checkers.TimeBefore,
	))
	s.AssertDischarge(c, noVisit, checkers.New(
		checkers.TimeBefore,
	))

	// Check that we can't discharge using the idm macaroon
	// when we've got a different origin header.
	b, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.Locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := b.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  idptest.DischargeLocation,
		Condition: "is-authenticated-user",
	}})
	c.Assert(err, gc.IsNil)
	s.BakeryClient.VisitWebPage = noVisit
	s.BakeryClient.Transport = originTransport{s.BakeryClient.Transport, "somewhere"}
	_, err = s.BakeryClient.DischargeAll(m)
	c.Assert(err, gc.ErrorMatches, `cannot get discharge from "https://idp.test": cannot start interactive session: unexpected call to visit`)
}

type originTransport struct {
	transport http.RoundTripper
	origin    string
}

func (t originTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h := make(http.Header)
	for attr, val := range req.Header {
		h[attr] = val
	}
	h.Set("Origin", t.origin)
	req1 := *req
	req1.Header = h
	return t.transport.RoundTrip(&req1)
}

func noVisit(*url.URL) error {
	return errors.New("unexpected call to visit")
}

func (s *dischargeSuite) TestDischargeAgentShortcut(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	err = s.IDMClient.SetUser(
		&params.SetUserRequest{
			Username: "testagent@admin@idm",
			User: params.User{
				Username: "testagent@admin@idm",
				Owner:    "admin@idm",
				PublicKeys: []*bakery.PublicKey{
					&key.Public,
				},
			},
		},
	)
	c.Assert(err, gc.IsNil)
	s.BakeryClient.Key = key
	u, err := url.Parse(idptest.DischargeLocation)
	agent.SetUpAuth(s.BakeryClient, u, "testagent@admin@idm")
	s.AssertDischarge(c, nil, checkers.New(
		checkers.TimeBefore,
	))
}

func (s *dischargeSuite) TestAdminDischarge(c *gc.C) {
	err := s.IDMClient.SetUser(
		&params.SetUserRequest{
			Username: "jbloggs",
			User: params.User{
				Username:   "jbloggs",
				ExternalID: "http://example.com/jbloggs",
				Email:      "jbloggs@example.com",
				FullName:   "Joe Bloggs",
				IDPGroups: []string{
					"test",
				},
			},
		},
	)
	c.Assert(err, gc.IsNil)
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.Locator,
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
			Location:  idptest.DischargeLocation,
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
			Location:  idptest.DischargeLocation,
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
			Location:  idptest.DischargeLocation,
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
			Location:  idptest.DischargeLocation,
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

			Location:  idptest.DischargeLocation,
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
			Location:  idptest.DischargeLocation,
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
		client.Transport = s.RoundTripper
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

func newMacaroon(c *gc.C, svc *bakery.Service, cav []checkers.Caveat) *macaroon.Macaroon {
	m, err := svc.NewMacaroon("", nil, cav)
	c.Assert(err, gc.IsNil)
	return m
}

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

func (s *dischargeSuite) TestDischargeMemberOf(c *gc.C) {
	visitor := test.WebPageVisitor{
		Client: s.HTTPRequestClient,
		User: &params.User{
			Username:   "test-user",
			ExternalID: "http://example.com/test-user",
			Email:      "test-user@example.com",
			FullName:   "Test User III",
			IDPGroups: []string{
				"test",
				"test2",
			},
		},
	}
	s.BakeryClient.VisitWebPage = visitor.Interactive
	// Create the service which will issue the third party caveat.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.Locator,
	})
	c.Assert(err, gc.IsNil)

	tests := []struct {
		about          string
		m              *macaroon.Macaroon
		expectError    string
		expectDeclared checkers.Declared
	}{{
		about: "test membership in single group - matches",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  idptest.DischargeLocation,
			Condition: "is-member-of test",
		}}),
		expectDeclared: checkers.Declared{},
	}, {
		about: "test membership in a set of groups",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  idptest.DischargeLocation,
			Condition: "is-member-of test test2",
		}}),
		expectDeclared: checkers.Declared{},
	}, {
		about: "test membership in single group - no match",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  idptest.DischargeLocation,
			Condition: "is-member-of test1",
		}}),
		expectError: "third party refused discharge: cannot discharge: user is not a member of required groups",
	}, {
		about: "test membership in a set of groups - one group matches",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  idptest.DischargeLocation,
			Condition: "is-member-of test2 test4",
		}}),
		expectDeclared: checkers.Declared{},
	}, {
		about: "test membership in a set of groups fail - no match",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  idptest.DischargeLocation,
			Condition: "is-member-of test1 test3",
		}}),
		expectError: "third party refused discharge: cannot discharge: user is not a member of required groups",
	},
	}

	for i, test := range tests {
		c.Logf("%d. %q", i, test.about)
		ms, err := s.BakeryClient.DischargeAll(test.m)
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

// This test is not sending the bakery protocol version so it will use the default
// one and return a 407.
func (s *dischargeSuite) TestDischargeStatusProxyAuthRequiredResponse(c *gc.C) {
	// Create the service which will issue the third party caveat.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.Locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := svc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  idptest.DischargeLocation,
		Condition: "is-authenticated-user",
	}})

	cav := m.Caveats()[0]
	resp, err := s.HTTPClient.PostForm(idptest.DischargeLocation+"/discharge", url.Values{
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
		Locator: s.Locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := svc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  idptest.DischargeLocation,
		Condition: "is-authenticated-user",
	}})

	cav := m.Caveats()[0]
	values := url.Values{
		"id":       {cav.Id},
		"location": {cav.Location},
	}

	req, err := http.NewRequest("POST", idptest.DischargeLocation+"/discharge", strings.NewReader(values.Encode()))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Bakery-Protocol-Version", "1")
	resp, err := s.HTTPClient.Do(req)
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()

	c.Assert(resp.StatusCode, gc.Equals, http.StatusUnauthorized)
	c.Assert(resp.Header.Get("WWW-Authenticate"), gc.Equals, "Macaroon")
}

func (s *dischargeSuite) TestDischargeLegacyLocation(c *gc.C) {
	visitor := &test.WebPageVisitor{
		Client: s.HTTPRequestClient,
		User:   s.user,
	}
	s.BakeryClient.VisitWebPage = visitor.Interactive
	pk, err := s.Locator.PublicKeyForLocation(idptest.DischargeLocation)
	c.Assert(err, gc.IsNil)
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: bakery.PublicKeyLocatorMap{
			idptest.DischargeLocation + "/v1/discharger": pk,
		},
	})
	c.Assert(err, gc.IsNil)
	ms, err := s.BakeryClient.DischargeAll(newMacaroon(c, svc, []checkers.Caveat{{
		Location:  idptest.DischargeLocation + "/v1/discharger",
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
	pk, err := s.Locator.PublicKeyForLocation(idptest.DischargeLocation)
	c.Assert(err, gc.IsNil)
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		URL:          idptest.DischargeLocation + "/v1/discharger/publickey",
		Do:           s.HTTPClient.Do,
		ExpectStatus: http.StatusOK,
		ExpectBody: map[string]*bakery.PublicKey{
			"PublicKey": pk,
		},
	})
}

func (s *dischargeSuite) TestPublicKey(c *gc.C) {
	pk, err := s.Locator.PublicKeyForLocation(idptest.DischargeLocation)
	c.Assert(err, gc.IsNil)
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		URL:          idptest.DischargeLocation + "/publickey",
		Do:           s.HTTPClient.Do,
		ExpectStatus: http.StatusOK,
		ExpectBody: map[string]*bakery.PublicKey{
			"PublicKey": pk,
		},
	})
}

func (s *dischargeSuite) TestIdentityCookieLocation(c *gc.C) {
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.Locator,
	})
	c.Assert(err, gc.IsNil)
	jar := new(testCookieJar)
	s.BakeryClient.Client.Jar = jar
	visitor := test.WebPageVisitor{
		Client: s.HTTPRequestClient,
		User:   s.user,
	}
	s.BakeryClient.VisitWebPage = visitor.Interactive
	m := newMacaroon(c, svc, []checkers.Caveat{{
		Location:  idptest.DischargeLocation,
		Condition: "is-authenticated-user",
	}})
	ms, err := s.BakeryClient.DischargeAll(m)
	c.Assert(err, gc.IsNil)
	d := checkers.InferDeclared(ms)
	err = svc.Check(ms, checkers.New(
		d,
		checkers.TimeBefore,
	))
	c.Assert(jar.cookies, gc.HasLen, 1)
	for k := range jar.cookies {
		c.Assert(k.path, gc.Equals, "/")
	}
}

type cookieKey struct {
	domain string
	path   string
	name   string
}

type testCookieJar struct {
	cookies map[cookieKey]*http.Cookie
}

func (j *testCookieJar) SetCookies(u *url.URL, cs []*http.Cookie) {
	if j.cookies == nil {
		j.cookies = make(map[cookieKey]*http.Cookie)
	}
	for _, c := range cs {
		key := cookieKey{
			domain: u.Host,
			path:   u.Path,
			name:   c.Name,
		}
		if c.Domain != "" {
			key.domain = c.Domain
		}
		if c.Path != "" {
			key.path = c.Path
		}
		j.cookies[key] = c
	}
}

func (j *testCookieJar) Cookies(u *url.URL) []*http.Cookie {
	return nil
}
