// Copyright 2014 Canonical Ltd.

package discharger_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/juju/testing/httptesting"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon.v2"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/test"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
	"github.com/CanonicalLtd/blues-identity/store"
)

var groupOp = bakery.Op{"group", "group"}

var testContext = context.Background()

type dischargeSuite struct {
	idmtest.DischargeSuite
}

var _ = gc.Suite(&dischargeSuite{})

func (s *dischargeSuite) SetUpTest(c *gc.C) {
	s.Params.IdentityProviders = []idp.IdentityProvider{
		test.NewIdentityProvider(test.Params{Name: "test", Domain: "test-domain"}),
	}
	s.DischargeSuite.SetUpTest(c)
}

func (s *dischargeSuite) TestInteractiveDischarge(c *gc.C) {
	s.AssertDischarge(c, webBrowserInteractor)
}

func (s *dischargeSuite) TestNonInteractiveDischarge(c *gc.C) {
	s.AssertDischarge(c, interactor)
}

func (s *dischargeSuite) TestDischargeWhenLoggedIn(c *gc.C) {
	client := s.Client(webBrowserInteractor)
	ms, err := s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	s.AssertMacaroon(c, ms, identchecker.LoginOp, "test-interactive")
	ms, err = s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	s.AssertMacaroon(c, ms, identchecker.LoginOp, "test-interactive")
}

func (s *dischargeSuite) TestVisitURLWithDomainCookie(c *gc.C) {
	u, err := url.Parse(s.URL + "/discharge")
	c.Assert(err, gc.Equals, nil)
	client := s.Client(nil)
	client.Client.Jar.SetCookies(u, []*http.Cookie{{
		Name:  "domain",
		Value: "test2",
	}})

	openWebBrowser := &valueSavingOpenWebBrowser{
		openWebBrowser: interactor.OpenWebBrowser,
	}
	client.AddInteractor(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: openWebBrowser.OpenWebBrowser,
	})
	_, err = s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	c.Assert(openWebBrowser.url.Query().Get("domain"), gc.Equals, "test2")
}

func (s *dischargeSuite) TestVisitURLWithInvalidDomainCookie(c *gc.C) {
	u, err := url.Parse(s.URL + "/discharge")
	c.Assert(err, gc.Equals, nil)
	client := s.Client(nil)
	client.Client.Jar.SetCookies(u, []*http.Cookie{{
		Name:  "domain",
		Value: "test2-",
	}})
	openWebBrowser := &valueSavingOpenWebBrowser{
		openWebBrowser: interactor.OpenWebBrowser,
	}
	client.AddInteractor(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: openWebBrowser.OpenWebBrowser,
	})
	_, err = s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	c.Assert(openWebBrowser.url.Query().Get("domain"), gc.Equals, "")
}

func (s *dischargeSuite) TestVisitURLWithEscapedDomainCookie(c *gc.C) {
	u, err := url.Parse(s.URL + "/discharge")
	c.Assert(err, gc.Equals, nil)
	client := s.Client(nil)
	client.Client.Jar.SetCookies(u, []*http.Cookie{{
		Name:  "domain",
		Value: "test+2",
	}})
	openWebBrowser := &valueSavingOpenWebBrowser{
		openWebBrowser: interactor.OpenWebBrowser,
	}
	client.AddInteractor(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: openWebBrowser.OpenWebBrowser,
	})
	_, err = s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	c.Assert(openWebBrowser.url.Query().Get("domain"), gc.Equals, "test+2")
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
	transport := t.transport
	if transport == nil {
		transport = &http.Transport{}
	}
	resp, err := transport.RoundTrip(req)
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
	c.Skip("cookies not yet supported")
	var disabled bool
	openWebBrowser := func(u *url.URL) error {
		if disabled {
			return errgo.New("visit required but not allowed")
		}
		return interactor.OpenWebBrowser(u)
	}
	client := s.Client(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: openWebBrowser,
	})
	_, err := s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	disabled = true
	_, err = s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)

	// Check that we can't discharge using the idm macaroon
	// when we've got a different origin header.
	client.Transport = originTransport{client.Transport, "somewhere"}
	_, err = s.Discharge(c, "is-authenticated-user", client)
	// TODO this error doesn't seem that closely related to the test failure condition.
	c.Assert(err, gc.ErrorMatches, `cannot get discharge from ".*": cannot start interactive session: unexpected call to visit`)
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
	transport := t.transport
	if transport == nil {
		transport = &http.Transport{}
	}
	return transport.RoundTrip(&req1)
}

var dischargeForUserTests = []struct {
	about            string
	condition        string
	username         string
	password         string
	dischargeForUser string
	m                *bakery.Macaroon
	expectUser       string
	expectErr        string
}{{
	about:            "discharge macaroon",
	condition:        "is-authenticated-user",
	username:         idmtest.AdminUsername,
	password:         idmtest.AdminPassword,
	dischargeForUser: "jbloggs",
	expectUser:       "jbloggs",
}, {
	about:            "no authentication",
	condition:        "is-authenticated-user",
	dischargeForUser: "jbloggs",
	expectErr:        `cannot get discharge from ".*": Post .*/discharge: macaroon discharge required: authentication required`,
}, {
	about:            "unsupported user",
	condition:        "is-authenticated-user",
	username:         idmtest.AdminUsername,
	password:         idmtest.AdminPassword,
	dischargeForUser: "jbloggs2",
	expectErr:        `cannot get discharge from ".*": Post .*/discharge: cannot discharge: could not determine identity: user jbloggs2 not found`,
}, {
	about:            "unsupported condition",
	condition:        "is-authenticated-group",
	username:         idmtest.AdminUsername,
	password:         idmtest.AdminPassword,
	dischargeForUser: "jbloggs",
	expectErr:        `.*caveat not recognized`,
}, {
	about:            "bad credentials",
	condition:        "is-authenticated-user",
	username:         "not-admin-username",
	password:         idmtest.AdminPassword,
	dischargeForUser: "jbloggs",
	expectErr:        `cannot get discharge from ".*": Post .*/discharge: cannot discharge: could not determine identity: invalid credentials`,
}, {
	about:            "is-authenticated-user with domain",
	condition:        "is-authenticated-user @test",
	username:         idmtest.AdminUsername,
	password:         idmtest.AdminPassword,
	dischargeForUser: "jbloggs@test",
	expectUser:       "jbloggs@test",
}, {
	about:            "is-authenticated-user with wrong domain",
	condition:        "is-authenticated-user @test2",
	username:         idmtest.AdminUsername,
	password:         idmtest.AdminPassword,
	dischargeForUser: "jbloggs@test",
	expectErr:        `cannot get discharge from ".*": Post .*/discharge: cannot discharge: could not determine identity: "jbloggs@test" not in required domain "test2"`,
}, {
	about:            "is-authenticated-user with invalid domain",
	condition:        "is-authenticated-user @test-",
	username:         idmtest.AdminUsername,
	password:         idmtest.AdminPassword,
	dischargeForUser: "jbloggs@test",
	expectErr:        `cannot get discharge from ".*": Post .*/discharge: cannot discharge: invalid domain "test-"`,
}, {
	about:            "invalid caveat",
	condition:        " invalid caveat",
	username:         idmtest.AdminUsername,
	password:         idmtest.AdminPassword,
	dischargeForUser: "jbloggs@test",
	expectErr:        `cannot get discharge from ".*": Post .*/discharge: cannot discharge: cannot parse caveat " invalid caveat": caveat starts with space character`,
}}

func (s *dischargeSuite) TestDischargeForUser(c *gc.C) {
	s.CreateUser(c, "jbloggs", "test")
	s.CreateUser(c, "jbloggs@test", "test")

	for i, test := range dischargeForUserTests {
		c.Logf("test %d. %s", i, test.about)
		da := &testDischargeAcquirer{
			client: &httprequest.Client{
				BaseURL: s.URL,
			},
			username:         test.username,
			password:         test.password,
			dischargeForUser: test.dischargeForUser,
		}
		ms, err := bakery.DischargeAll(
			s.Ctx,
			s.NewMacaroon(c, test.condition, identchecker.LoginOp),
			da.AcquireDischarge,
		)
		if test.expectErr != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErr)
			continue
		}
		c.Assert(err, gc.Equals, nil)
		ui, err := s.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
		c.Assert(ui.Identity.Id(), gc.Equals, test.expectUser)
	}
}

// testDischargeAcquirer acquires a discharge by using the provided basic
// authentication credentials to perform an discharge as the specified
// user.
type testDischargeAcquirer struct {
	client             *httprequest.Client
	username, password string
	dischargeForUser   string
}

func (da *testDischargeAcquirer) AcquireDischarge(ctx context.Context, cav macaroon.Caveat, payload []byte) (*bakery.Macaroon, error) {
	u, err := url.Parse(cav.Location)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	u.Path = path.Join(u.Path, "discharge")
	params := make(url.Values)
	if len(payload) > 0 {
		params.Set("id64", base64.RawURLEncoding.EncodeToString(cav.Id))
		params.Set("caveat64", base64.RawURLEncoding.EncodeToString(payload))
	} else {
		params.Set("id64", base64.RawURLEncoding.EncodeToString(cav.Id))
	}
	if da.dischargeForUser != "" {
		params.Set("discharge-for-user", da.dischargeForUser)
	}
	req, err := http.NewRequest("POST", u.String(), strings.NewReader(params.Encode()))
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if da.username != "" {
		req.SetBasicAuth(da.username, da.password)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var dr dischargeResponse
	if err := da.client.Do(ctx, req, &dr); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return dr.Macaroon, nil
}

type dischargeResponse struct {
	Macaroon *bakery.Macaroon `json:",omitempty"`
}

var dischargeMemberOfTests = []struct {
	about       string
	condition   string
	expectError string
}{{
	about:     "test-user is member of group test-user",
	condition: "is-member-of test-user",
}, {
	about:     "test-user is member of group test-user with multiple groups",
	condition: "is-member-of test-user testX testY",
}, {
	about:     "test membership in single group - matches",
	condition: "is-member-of test",
}, {
	about:     "test membership in a set of groups",
	condition: "is-member-of test test2",
}, {
	about:       "test membership in single group - no match",
	condition:   "is-member-of test1",
	expectError: `cannot get discharge from ".*": Post http.*: permission denied`,
}, {
	about:     "test membership in a set of groups - one group matches",
	condition: "is-member-of test2 test4",
}, {
	about:       "test membership in a set of groups fail - no match",
	condition:   "is-member-of test1 test3",
	expectError: `cannot get discharge from ".*": Post http.*: permission denied`,
}}

func (s *dischargeSuite) TestDischargeMemberOf(c *gc.C) {
	client := s.Client(test.Interactor{
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
	})
	ctx := context.Background()
	for i, test := range dischargeMemberOfTests {
		c.Logf("%d. %q", i, test.about)
		m := s.NewMacaroon(c, test.condition, groupOp)
		ms, err := client.DischargeAll(ctx, m)
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			continue
		}
		c.Assert(err, gc.Equals, nil)
		s.AssertMacaroon(c, ms, groupOp, "")
	}
}

func (s *dischargeSuite) TestDischargeXMemberOfX(c *gc.C) {
	// if the user is X member of no group, we must still
	// discharge is-member-of X.
	client := s.Client(test.Interactor{
		User: &params.User{
			Username:   "test-user",
			ExternalID: "http://example.com/test-user",
			Email:      "test-user@example.com",
			FullName:   "Test User III",
			IDPGroups:  []string{},
		},
	})

	m := s.NewMacaroon(c, "is-member-of test-user", groupOp)
	ms, err := client.DischargeAll(context.Background(), m)
	c.Assert(err, gc.Equals, nil)
	s.AssertMacaroon(c, ms, groupOp, "")
}

// This test is not sending the bakery protocol version so it will use the default
// one and return a 407.
func (s *dischargeSuite) TestDischargeStatusProxyAuthRequiredResponse(c *gc.C) {
	// Make a version 1 macaroon so that the caveat is in the macaroon
	// and it's appropriate for a 407-era macaroon.
	m, err := s.Bakery.Oven.NewMacaroon(
		testContext,
		bakery.Version1,
		[]checkers.Caveat{{
			Location:  s.URL,
			Condition: "is-authenticated-user",
		}},
		identchecker.LoginOp,
	)
	c.Assert(err, gc.IsNil)

	var thirdPartyCaveat macaroon.Caveat
	for _, cav := range m.M().Caveats() {
		if cav.VerificationId != nil {
			thirdPartyCaveat = cav
			break
		}
	}
	c.Assert(thirdPartyCaveat.Id, gc.Not(gc.Equals), "")
	resp, err := http.PostForm(s.URL+"/discharge", url.Values{
		"id":       {string(thirdPartyCaveat.Id)},
		"location": {thirdPartyCaveat.Location},
	})
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()

	c.Assert(resp.StatusCode, gc.Equals, http.StatusProxyAuthRequired)
}

// This test is using the bakery protocol version at value 1 to be able to return a 401
// instead of a 407
func (s *dischargeSuite) TestDischargeStatusUnauthorizedResponse(c *gc.C) {
	// Make a version 2 macaroon so that the caveat is in the macaroon.
	m, err := s.Bakery.Oven.NewMacaroon(
		testContext,
		bakery.Version2,
		[]checkers.Caveat{{
			Location:  s.URL,
			Condition: "is-authenticated-user",
		}},
		identchecker.LoginOp,
	)
	c.Assert(err, gc.IsNil)

	var thirdPartyCaveat macaroon.Caveat
	for _, cav := range m.M().Caveats() {
		if cav.VerificationId != nil {
			thirdPartyCaveat = cav
			break
		}
	}
	c.Assert(thirdPartyCaveat.Id, gc.Not(gc.Equals), "")
	values := url.Values{
		"id":       {string(thirdPartyCaveat.Id)},
		"location": {thirdPartyCaveat.Location},
	}

	req, err := http.NewRequest("POST", s.URL+"/discharge", strings.NewReader(values.Encode()))
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Bakery-Protocol-Version", "1")
	resp, err := http.DefaultClient.Do(req)
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()

	c.Assert(resp.StatusCode, gc.Equals, http.StatusUnauthorized)
	c.Assert(resp.Header.Get("WWW-Authenticate"), gc.Equals, "Macaroon")
}

func (s *dischargeSuite) TestPublicKey(c *gc.C) {
	info, err := s.ThirdPartyInfo(testContext, s.URL)
	c.Assert(err, gc.IsNil)
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		URL:          s.URL + "/publickey",
		ExpectStatus: http.StatusOK,
		ExpectBody: map[string]*bakery.PublicKey{
			"PublicKey": &info.PublicKey,
		},
	})
}

// TODO(mhilton): Work out how to deal with identity cookies later.
func (s *dischargeSuite) TestIdentityCookieParameters(c *gc.C) {
	c.Skip("cookies not yet supported")
	client := s.Client(webBrowserInteractor)
	jar := new(testCookieJar)
	client.Client.Jar = jar
	ms, err := s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	s.AssertMacaroon(c, ms, identchecker.LoginOp, "test-interactive")
	c.Assert(jar.cookies, gc.HasLen, 1)
	for k := range jar.cookies {
		c.Assert(k.name, gc.Equals, "macaroon-identity")
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

func (s *dischargeSuite) TestLastDischargeTimeUpdates(c *gc.C) {
	s.AssertDischarge(c, webBrowserInteractor)
	id1 := store.Identity{
		ProviderID: "test:test-interactive",
	}
	err := s.Params.Store.Identity(context.Background(), &id1)
	c.Assert(err, gc.Equals, nil)
	c.Assert(id1.LastDischarge.IsZero(), gc.Equals, false)

	// Wait at least one ms so that the discharge time stored in the
	// database is necessarily different.
	time.Sleep(time.Millisecond)

	s.AssertDischarge(c, webBrowserInteractor)
	id2 := store.Identity{
		ProviderID: "test:test-interactive",
	}
	err = s.Params.Store.Identity(context.Background(), &id2)
	c.Assert(err, gc.Equals, nil)
	c.Assert(id2.LastDischarge.After(id1.LastDischarge), gc.Equals, true)
}

var domainInteractionURLTests = []struct {
	about        string
	condition    string
	cookies      map[string]string
	expectDomain string
}{{
	about:        "domain login",
	condition:    "is-authenticated-user @test-domain",
	expectDomain: "test-domain",
}, {
	about:     "no domain",
	condition: "is-authenticated-user",
}, {
	about:     "domain from cookies",
	condition: "is-authenticated-user",
	cookies: map[string]string{
		"domain": "cookie-domain",
	},
	expectDomain: "cookie-domain",
}, {
	about:     "condition trumps cookies",
	condition: "is-authenticated-user @test-domain",
	cookies: map[string]string{
		"domain": "cookie-domain",
	},
	expectDomain: "test-domain",
}}

func (s *dischargeSuite) TestDomainInInteractionURLs(c *gc.C) {
	for i, tst := range domainInteractionURLTests {
		c.Logf("test %d. %s", i, tst.about)
		username := "user"
		if tst.expectDomain != "" {
			username = "user@" + tst.expectDomain
		}
		interactor := &test.Interactor{
			User: &params.User{
				Username:   params.Username(username),
				ExternalID: tst.expectDomain + ":user",
			},
		}
		client := s.Client(httpbakery.WebBrowserInteractor{
			OpenWebBrowser: interactor.OpenWebBrowser,
		})
		interactor.Doer = client
		for k, v := range tst.cookies {
			u, err := url.Parse(s.URL)
			c.Assert(err, gc.IsNil)
			client.Jar.SetCookies(u, []*http.Cookie{{
				Name:  k,
				Value: v,
			}})
		}
		ms, err := s.Discharge(c, tst.condition, client)
		c.Assert(err, gc.Equals, nil)
		s.AssertMacaroon(c, ms, identchecker.LoginOp, username)
	}
}

func (s *dischargeSuite) TestDischargeWithDomainWithExistingNonDomainAuth(c *gc.C) {
	// First log in successfully without a domain.
	s.AssertDischarge(c, &test.Interactor{
		User: &params.User{
			Username:   "bob",
			ExternalID: "bobexternal",
		},
	})
	// Then try with a caveat that requires a domain.
	ms, err := s.Discharge(c, "is-authenticated-user @test-domain", s.Client(&test.Interactor{
		User: &params.User{
			Username:   "alice@test-domain",
			ExternalID: "aliceexternal",
		},
	}))
	c.Assert(err, gc.Equals, nil)
	s.AssertMacaroon(c, ms, identchecker.LoginOp, "alice@test-domain")
}

var interactor = &test.Interactor{
	User: &params.User{
		Username:   "test-interactive",
		ExternalID: "test:test-interactive",
		FullName:   "Interactive Test User",
		Email:      "test-interactive@example.com",
		IDPGroups:  []string{"test1", "test2"},
	},
}

var webBrowserInteractor = httpbakery.WebBrowserInteractor{
	OpenWebBrowser: interactor.OpenWebBrowser,
}

type valueSavingOpenWebBrowser struct {
	url            *url.URL
	openWebBrowser func(u *url.URL) error
}

func (v *valueSavingOpenWebBrowser) OpenWebBrowser(u *url.URL) error {
	v.url = u
	return v.openWebBrowser(u)
}
