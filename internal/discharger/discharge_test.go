// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/juju/qthttptest"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v3/bakery"
	"gopkg.in/macaroon-bakery.v3/bakery/checkers"
	"gopkg.in/macaroon-bakery.v3/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v3/httpbakery"
	"gopkg.in/macaroon.v2"

	"github.com/canonical/candid/candidclient"
	"github.com/canonical/candid/candidclient/redirect"
	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/static"
	"github.com/canonical/candid/internal/auth"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/internal/discharger"
	"github.com/canonical/candid/internal/identity"
	v1 "github.com/canonical/candid/internal/v1"
	"github.com/canonical/candid/params"
	"github.com/canonical/candid/store"
)

var groupOp = bakery.Op{"group", "group"}

var testContext = context.Background()

func TestDischarge(t *testing.T) {
	qtsuite.Run(qt.New(t), &dischargeSuite{})
}

type dischargeSuite struct {
	srv              *candidtest.Server
	store            *candidtest.Store
	dischargeCreator *candidtest.DischargeCreator
	interactor       httpbakery.WebBrowserInteractor
}

func (s *dischargeSuite) Init(c *qt.C) {
	s.store = candidtest.NewStore()
	sp := s.store.ServerParams()
	sp.AdminPassword = "test-password"
	sp.IdentityProviders = []idp.IdentityProvider{
		static.NewIdentityProvider(static.Params{
			Name:   "test",
			Domain: "",
			Users: map[string]static.UserInfo{
				"test": {
					Password: "password",
					Name:     "Test User",
					Email:    "test@example.com",
					Groups:   []string{"test1", "test2"},
				},
				"test2": {
					Password: "password2",
					Name:     "Test User II",
					Email:    "test2@example.com",
				},
			},
			Icon: "/static/idp.pcx",
		}),
		static.NewIdentityProvider(static.Params{
			Name:   "test-domain",
			Domain: "test-domain",
			Users: map[string]static.UserInfo{
				"test": {
					Password: "password",
					Name:     "Test User",
					Email:    "test@example.com",
					Groups:   []string{"test1", "test2"},
				},
			},
			Icon: "/static/idp-test-domain.pcx",
		}),
		static.NewIdentityProvider(static.Params{
			Name:   "test-cookie-domain",
			Domain: "cookie-domain",
			Users: map[string]static.UserInfo{
				"test": {
					Password: "password",
					Name:     "Test User",
					Email:    "test@example.com",
					Groups:   []string{"test1", "test2"},
				},
			},
		}),
	}
	sp.RedirectLoginWhitelist = []string{
		"https://www.example.com/callback",
	}
	s.srv = candidtest.NewServer(c, sp, map[string]identity.NewAPIHandlerFunc{
		"discharger": discharger.NewAPIHandler,
		"v1":         v1.NewAPIHandler,
	})
	s.dischargeCreator = candidtest.NewDischargeCreator(s.srv)
	s.interactor = httpbakery.WebBrowserInteractor{
		OpenWebBrowser: candidtest.PasswordLogin(c, "test", "password"),
	}
}

func (s *dischargeSuite) TestInteractiveDischarge(c *qt.C) {
	s.dischargeCreator.AssertDischarge(c, s.interactor)
}

func (s *dischargeSuite) TestNonInteractiveDischarge(c *qt.C) {
	client := s.srv.AdminClient()
	ms, err := s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.IsNil)
	s.dischargeCreator.AssertMacaroon(c, ms, identchecker.LoginOp, auth.AdminUsername)
}

func (s *dischargeSuite) TestInteractiveDischargeWithOldClientCaveat(c *qt.C) {
	ms, err := s.dischargeCreator.Discharge(c, "<is-authenticated-user", s.srv.Client(s.interactor))
	c.Assert(err, qt.IsNil)
	_, err = s.dischargeCreator.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Assert(err, qt.IsNil)
}

func (s *dischargeSuite) TestInteractiveDischargeJSON(c *qt.C) {
	openWebBrowser := func(u *url.URL) error {
		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Add("Accept", "application/json")
		resp, err := s.srv.Client(nil).Do(req)
		if err != nil {
			return err
		}
		payload := &params.IDPChoice{}
		err = httprequest.UnmarshalJSONResponse(resp, payload)
		c.Assert(resp.Header.Get("Content-Type"), qt.Equals, "application/json")
		c.Assert(len(payload.IDPs) > 1, qt.Equals, true)
		// do normal interactive login
		return s.interactor.OpenWebBrowser(u)
	}
	client := s.srv.Client(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: openWebBrowser,
	})
	_, err := s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.IsNil)
}

func (s *dischargeSuite) TestTwoDischargesOfSameCaveat(c *qt.C) {
	// First make start an interaction-required discharge, but don't
	// allow it to complete immediately.
	interacting := make(chan struct{})
	done := make(chan struct{})

	// Create a macaroon that we'll try to discharge twice concurrently.
	m := s.dischargeCreator.NewMacaroon(c, "is-authenticated-user", identchecker.LoginOp)
	go func() {
		client := s.srv.Client(httpbakery.WebBrowserInteractor{
			OpenWebBrowser: func(u *url.URL) error {
				interacting <- struct{}{}
				<-interacting
				return s.interactor.OpenWebBrowser(u)
			},
		})
		ms, err := client.DischargeAll(s.srv.Ctx, m)
		c.Check(err, qt.Equals, nil)
		_, err = s.dischargeCreator.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
		c.Check(err, qt.Equals, nil)
		close(done)
	}()
	<-interacting
	// The first discharge is now stuck in OpenWebBrowser until we
	// tell it to go ahead, so try to discharge the same macaroon that
	// we just tried.
	client := s.srv.Client(s.interactor)
	ms, err := client.DischargeAll(s.srv.Ctx, m)
	c.Check(err, qt.Equals, nil)
	_, err = s.dischargeCreator.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Check(err, qt.Equals, nil)

	// Let the other one proceed - it should succeed too.
	interacting <- struct{}{}
	<-done
}

func (s *dischargeSuite) TestDischargeWhenLoggedIn(c *qt.C) {
	client := s.srv.Client(s.interactor)
	ms, err := s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.IsNil)
	s.dischargeCreator.AssertMacaroon(c, ms, identchecker.LoginOp, "test")
	ms, err = s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.IsNil)
	s.dischargeCreator.AssertMacaroon(c, ms, identchecker.LoginOp, "test")
}

func (s *dischargeSuite) TestVisitURLWithDomainCookie(c *qt.C) {
	u, err := url.Parse(s.srv.URL + "/discharge")
	c.Assert(err, qt.IsNil)
	client := s.srv.Client(nil)
	client.Client.Jar.SetCookies(u, []*http.Cookie{{
		Name:  "domain",
		Value: "test2",
	}})

	openWebBrowser := &valueSavingOpenWebBrowser{
		openWebBrowser: s.interactor.OpenWebBrowser,
	}
	client.AddInteractor(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: openWebBrowser.OpenWebBrowser,
	})
	_, err = s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.IsNil)
	c.Assert(openWebBrowser.url.Query().Get("domain"), qt.Equals, "test2")
}

func (s *dischargeSuite) TestVisitURLWithInvalidDomainCookie(c *qt.C) {
	u, err := url.Parse(s.srv.URL + "/discharge")
	c.Assert(err, qt.IsNil)
	client := s.srv.Client(nil)
	client.Client.Jar.SetCookies(u, []*http.Cookie{{
		Name:  "domain",
		Value: "test2-",
	}})
	openWebBrowser := &valueSavingOpenWebBrowser{
		openWebBrowser: s.interactor.OpenWebBrowser,
	}
	client.AddInteractor(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: openWebBrowser.OpenWebBrowser,
	})
	_, err = s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.IsNil)
	c.Assert(openWebBrowser.url.Query().Get("domain"), qt.Equals, "")
}

func (s *dischargeSuite) TestVisitURLWithEscapedDomainCookie(c *qt.C) {
	u, err := url.Parse(s.srv.URL + "/discharge")
	c.Assert(err, qt.IsNil)
	client := s.srv.Client(nil)
	client.Client.Jar.SetCookies(u, []*http.Cookie{{
		Name:  "domain",
		Value: "test+2",
	}})
	openWebBrowser := &valueSavingOpenWebBrowser{
		openWebBrowser: s.interactor.OpenWebBrowser,
	}
	client.AddInteractor(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: openWebBrowser.OpenWebBrowser,
	})
	_, err = s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.IsNil)
	c.Assert(openWebBrowser.url.Query().Get("domain"), qt.Equals, "test+2")
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
	c         *qt.C
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

func (s *dischargeSuite) TestDischargeFromDifferentOriginWhenLoggedIn(c *qt.C) {
	c.Skip("origin caveats on identity cookies not yet supported")
	var disabled bool
	openWebBrowser := func(u *url.URL) error {
		if disabled {
			return errgo.New("visit required but not allowed")
		}
		return s.interactor.OpenWebBrowser(u)
	}
	client := s.srv.Client(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: openWebBrowser,
	})
	_, err := s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.IsNil)
	disabled = true
	_, err = s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.IsNil)

	// Check that we can't discharge using the candid macaroon
	// when we've got a different origin header.
	client.Transport = originTransport{client.Transport, "somewhere"}
	_, err = s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	// TODO this error doesn't seem that closely related to the test failure condition.
	c.Assert(err, qt.ErrorMatches, `cannot get discharge from ".*": cannot start interactive session: unexpected call to visit`)
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
	username:         "admin",
	password:         "test-password",
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
	username:         "admin",
	password:         "test-password",
	dischargeForUser: "jbloggs2",
	expectErr:        `cannot get discharge from ".*": Post .*/discharge: cannot discharge: could not determine identity: user jbloggs2 not found`,
}, {
	about:            "unsupported condition",
	condition:        "is-authenticated-group",
	username:         "admin",
	password:         "test-password",
	dischargeForUser: "jbloggs",
	expectErr:        `.*caveat not recognized`,
}, {
	about:            "bad credentials",
	condition:        "is-authenticated-user",
	username:         "not-admin-username",
	password:         "test-password",
	dischargeForUser: "jbloggs",
	expectErr:        `cannot get discharge from ".*": Post .*/discharge: cannot discharge: could not determine identity: invalid credentials`,
}, {
	about:            "is-authenticated-user with domain",
	condition:        "is-authenticated-user @test",
	username:         "admin",
	password:         "test-password",
	dischargeForUser: "jbloggs@test",
	expectUser:       "jbloggs@test",
}, {
	about:            "is-authenticated-user with wrong domain",
	condition:        "is-authenticated-user @test2",
	username:         "admin",
	password:         "test-password",
	dischargeForUser: "jbloggs@test",
	expectErr:        `cannot get discharge from ".*": Post .*/discharge: cannot discharge: could not determine identity: "jbloggs@test" not in required domain "test2"`,
}, {
	about:            "is-authenticated-user with invalid domain",
	condition:        "is-authenticated-user @test-",
	username:         "admin",
	password:         "test-password",
	dischargeForUser: "jbloggs@test",
	expectErr:        `cannot get discharge from ".*": Post .*/discharge: cannot discharge: invalid domain "test-"`,
}, {
	about:            "invalid caveat",
	condition:        " invalid caveat",
	username:         "admin",
	password:         "test-password",
	dischargeForUser: "jbloggs@test",
	expectErr:        `cannot get discharge from ".*": Post .*/discharge: cannot discharge: cannot parse caveat " invalid caveat": caveat starts with space character`,
}}

func (s *dischargeSuite) TestDischargeForUser(c *qt.C) {
	s.srv.CreateUser(c, "jbloggs", "test")
	s.srv.CreateUser(c, "jbloggs@test", "test")

	for i, test := range dischargeForUserTests {
		c.Logf("test %d. %s", i, test.about)
		da := &testDischargeAcquirer{
			client: &httprequest.Client{
				BaseURL: s.srv.URL,
			},
			username:         test.username,
			password:         test.password,
			dischargeForUser: test.dischargeForUser,
		}
		ms, err := bakery.DischargeAll(
			s.srv.Ctx,
			s.dischargeCreator.NewMacaroon(c, test.condition, identchecker.LoginOp),
			da.AcquireDischarge,
		)
		if test.expectErr != "" {
			c.Assert(err, qt.ErrorMatches, test.expectErr)
			continue
		}
		c.Assert(err, qt.IsNil)
		ui, err := s.dischargeCreator.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
		c.Assert(ui.Identity.Id(), qt.Equals, test.expectUser)
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
	name        string
	condition   string
	expectError string
}{{
	name:      "SingleGroupsIsUsername",
	condition: "is-member-of test",
}, {
	name:      "ManyGroupsOneIsUsername",
	condition: "is-member-of test testX testY",
}, {
	name:      "SingleGroupMatch",
	condition: "is-member-of test1",
}, {
	name:      "ManyGroupsAllMatch",
	condition: "is-member-of test1 test2",
}, {
	name:        "SingleGroupNoMatch",
	condition:   "is-member-of test3",
	expectError: `cannot get discharge from ".*": Post http.*: permission denied`,
}, {
	name:      "ManyGroupsOneMatches",
	condition: "is-member-of test2 test4",
}, {
	name:        "ManyGroupsNoMatch",
	condition:   "is-member-of test3 test4",
	expectError: `cannot get discharge from ".*": Post http.*: permission denied`,
}}

func (s *dischargeSuite) TestDischargeMemberOf(c *qt.C) {
	client := s.srv.Client(s.interactor)
	ctx := context.Background()
	for _, test := range dischargeMemberOfTests {
		c.Run(test.name, func(c *qt.C) {
			m := s.dischargeCreator.NewMacaroon(c, test.condition, groupOp)
			ms, err := client.DischargeAll(ctx, m)
			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				return
			}
			c.Assert(err, qt.IsNil)
			s.dischargeCreator.AssertMacaroon(c, ms, groupOp, "")
		})
	}
}

func (s *dischargeSuite) TestDischargeXMemberOfX(c *qt.C) {
	// if the user is X member of no group, we must still
	// discharge is-member-of X.
	client := s.srv.Client(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: candidtest.PasswordLogin(c, "test2", "password2"),
	})

	m := s.dischargeCreator.NewMacaroon(c, "is-member-of test2", groupOp)
	ms, err := client.DischargeAll(context.Background(), m)
	c.Assert(err, qt.IsNil)
	s.dischargeCreator.AssertMacaroon(c, ms, groupOp, "")
}

// This test is not sending the bakery protocol version so it will use the default
// one and return a 407.
func (s *dischargeSuite) TestDischargeStatusProxyAuthRequiredResponse(c *qt.C) {
	// Make a version 1 macaroon so that the caveat is in the macaroon
	// and it's appropriate for a 407-era macaroon.
	m, err := s.dischargeCreator.Bakery.Oven.NewMacaroon(
		testContext,
		bakery.Version1,
		[]checkers.Caveat{{
			Location:  s.srv.URL,
			Condition: "is-authenticated-user",
		}},
		identchecker.LoginOp,
	)
	c.Assert(err, qt.IsNil)

	var thirdPartyCaveat macaroon.Caveat
	for _, cav := range m.M().Caveats() {
		if cav.VerificationId != nil {
			thirdPartyCaveat = cav
			break
		}
	}
	c.Assert(thirdPartyCaveat.Id, qt.Not(qt.Equals), "")
	resp, err := http.PostForm(s.srv.URL+"/discharge", url.Values{
		"id":       {string(thirdPartyCaveat.Id)},
		"location": {thirdPartyCaveat.Location},
	})
	c.Assert(err, qt.IsNil)
	defer resp.Body.Close()

	c.Assert(resp.StatusCode, qt.Equals, http.StatusProxyAuthRequired)
}

// This test is using the bakery protocol version at value 1 to be able to return a 401
// instead of a 407
func (s *dischargeSuite) TestDischargeStatusUnauthorizedResponse(c *qt.C) {
	// Make a version 2 macaroon so that the caveat is in the macaroon.
	m, err := s.dischargeCreator.Bakery.Oven.NewMacaroon(
		testContext,
		bakery.Version2,
		[]checkers.Caveat{{
			Location:  s.srv.URL,
			Condition: "is-authenticated-user",
		}},
		identchecker.LoginOp,
	)
	c.Assert(err, qt.IsNil)

	var thirdPartyCaveat macaroon.Caveat
	for _, cav := range m.M().Caveats() {
		if cav.VerificationId != nil {
			thirdPartyCaveat = cav
			break
		}
	}
	c.Assert(thirdPartyCaveat.Id, qt.Not(qt.Equals), "")
	values := url.Values{
		"id":       {string(thirdPartyCaveat.Id)},
		"location": {thirdPartyCaveat.Location},
	}

	req, err := http.NewRequest("POST", s.srv.URL+"/discharge", strings.NewReader(values.Encode()))
	c.Assert(err, qt.IsNil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Bakery-Protocol-Version", "1")
	resp, err := http.DefaultClient.Do(req)
	c.Assert(err, qt.IsNil)
	defer resp.Body.Close()

	c.Assert(resp.StatusCode, qt.Equals, http.StatusUnauthorized)
	c.Assert(resp.Header.Get("WWW-Authenticate"), qt.Equals, "Macaroon")
}

func (s *dischargeSuite) TestPublicKey(c *qt.C) {
	info, err := s.srv.ThirdPartyInfo(testContext, s.srv.URL)
	c.Assert(err, qt.IsNil)
	qthttptest.AssertJSONCall(c, qthttptest.JSONCallParams{
		URL:          s.srv.URL + "/publickey",
		ExpectStatus: http.StatusOK,
		ExpectBody: map[string]*bakery.PublicKey{
			"PublicKey": &info.PublicKey,
		},
	})
}

func (s *dischargeSuite) TestIdentityCookieParameters(c *qt.C) {
	client := s.srv.Client(s.interactor)
	jar := new(testCookieJar)
	client.Client.Jar = jar
	ms, err := s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.IsNil)
	s.dischargeCreator.AssertMacaroon(c, ms, identchecker.LoginOp, "test")
	c.Assert(jar.cookies, qt.HasLen, 1)
	for k := range jar.cookies {
		c.Assert(k.name, qt.Equals, "macaroon-identity")
		c.Assert(k.path, qt.Equals, "/")
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

func (s *dischargeSuite) TestLastDischargeTimeUpdates(c *qt.C) {
	s.dischargeCreator.AssertDischarge(c, s.interactor)
	id1 := store.Identity{
		ProviderID: "test:test",
	}
	err := s.store.Store.Identity(context.Background(), &id1)
	c.Assert(err, qt.IsNil)
	c.Assert(id1.LastDischarge.IsZero(), qt.Equals, false)

	// Wait at least one ms so that the discharge time stored in the
	// database is necessarily different.
	time.Sleep(time.Millisecond)

	s.dischargeCreator.AssertDischarge(c, s.interactor)
	id2 := store.Identity{
		ProviderID: "test:test",
	}
	err = s.store.Store.Identity(context.Background(), &id2)
	c.Assert(err, qt.IsNil)
	c.Assert(id2.LastDischarge.After(id1.LastDischarge), qt.Equals, true)
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

func (s *dischargeSuite) TestDomainInInteractionURLs(c *qt.C) {
	for _, tst := range domainInteractionURLTests {
		c.Run(tst.about, func(c *qt.C) {
			client := s.srv.Client(s.interactor)
			for k, v := range tst.cookies {
				u, err := url.Parse(s.srv.URL)
				c.Assert(err, qt.IsNil)
				client.Jar.SetCookies(u, []*http.Cookie{{
					Name:  k,
					Value: v,
				}})
			}
			ms, err := s.dischargeCreator.Discharge(c, tst.condition, client)
			c.Assert(err, qt.IsNil)
			username := "test"
			if tst.expectDomain != "" {
				username = "test@" + tst.expectDomain
			}
			s.dischargeCreator.AssertMacaroon(c, ms, identchecker.LoginOp, username)
		})
	}
}

func (s *dischargeSuite) TestDischargeWithDomainWithExistingNonDomainAuth(c *qt.C) {
	// First log in successfully without a domain.
	s.dischargeCreator.AssertDischarge(c, s.interactor)
	// Then try with a caveat that requires a domain.
	ms, err := s.dischargeCreator.Discharge(c, "is-authenticated-user @test-domain", s.srv.Client(s.interactor))
	c.Assert(err, qt.IsNil)
	s.dischargeCreator.AssertMacaroon(c, ms, identchecker.LoginOp, "test@test-domain")
}

type valueSavingOpenWebBrowser struct {
	url            *url.URL
	openWebBrowser func(u *url.URL) error
}

func (v *valueSavingOpenWebBrowser) OpenWebBrowser(u *url.URL) error {
	v.url = u
	return v.openWebBrowser(u)
}

func (s *dischargeSuite) TestDischargeBrowserRedirectLogin(c *qt.C) {
	interactor := new(redirect.Interactor)
	_, err := s.dischargeCreator.Discharge(c, "is-authenticated-user", s.srv.Client(interactor))
	c.Assert(httpbakery.IsInteractionError(errgo.Cause(err)), qt.Equals, true, qt.Commentf("%v", errgo.Details(errgo.Cause(err))))
	ierr := errgo.Cause(err).(*httpbakery.InteractionError)
	c.Assert(redirect.IsRedirectRequiredError(errgo.Cause(ierr.Reason)), qt.Equals, true)
	rerr := errgo.Cause(ierr.Reason).(*redirect.RedirectRequiredError)

	jar, err := cookiejar.New(nil)
	c.Assert(err, qt.IsNil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host == "www.example.com" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := client.Get(rerr.InteractionInfo.RedirectURL("https://www.example.com/callback", "123456"))
	c.Assert(err, qt.IsNil)

	f := candidtest.SelectInteractiveLogin(candidtest.PostLoginForm("test", "password"))
	resp, err = f(client, resp)
	c.Assert(err, qt.IsNil)
	defer resp.Body.Close()

	c.Assert(resp.StatusCode, qt.Equals, http.StatusSeeOther, qt.Commentf("unexpected response %q", resp.Status))
	state, code, err := redirect.ParseLoginResult(resp.Header.Get("Location"))
	c.Assert(err, qt.IsNil)
	c.Assert(state, qt.Equals, "123456")

	dt, err := rerr.InteractionInfo.GetDischargeToken(context.Background(), code)
	c.Assert(err, qt.IsNil)

	interactor.SetDischargeToken(rerr.InteractionInfo.LoginURL, dt)
	ms, err := s.dischargeCreator.Discharge(c, "is-authenticated-user", s.srv.Client(interactor))
	c.Assert(err, qt.IsNil)
	s.dischargeCreator.AssertMacaroon(c, ms, identchecker.LoginOp, "")
}

func (s *dischargeSuite) TestDischargeBrowserRedirectLoginNotWhitelisted(c *qt.C) {
	interactor := new(redirect.Interactor)
	_, err := s.dischargeCreator.Discharge(c, "is-authenticated-user", s.srv.Client(interactor))
	c.Assert(httpbakery.IsInteractionError(errgo.Cause(err)), qt.Equals, true, qt.Commentf("%v", errgo.Details(errgo.Cause(err))))
	ierr := errgo.Cause(err).(*httpbakery.InteractionError)
	c.Assert(redirect.IsRedirectRequiredError(errgo.Cause(ierr.Reason)), qt.Equals, true)
	rerr := errgo.Cause(ierr.Reason).(*redirect.RedirectRequiredError)

	jar, err := cookiejar.New(nil)
	c.Assert(err, qt.IsNil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host == "www.example.com" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := client.Get(rerr.InteractionInfo.RedirectURL("https://www.example.com/callback2", "123456"))
	c.Assert(err, qt.IsNil)

	f := candidtest.SelectInteractiveLogin(candidtest.PostLoginForm("test", "password"))
	resp, err = f(client, resp)
	c.Assert(err, qt.IsNil)
	defer resp.Body.Close()

	c.Assert(resp.StatusCode, qt.Equals, http.StatusBadRequest, qt.Commentf("unexpected response %q", resp.Status))
	var perr params.Error
	err = httprequest.UnmarshalJSONResponse(resp, &perr)
	c.Assert(err, qt.IsNil)
	c.Assert(&perr, qt.ErrorMatches, "invalid return_to")
}

func (s *dischargeSuite) TestDischargeUserID(c *qt.C) {
	dc := candidtest.NewUserIDDischargeCreator(s.srv)
	client := s.srv.AdminClient()
	ms, err := dc.Discharge(c, "is-authenticated-userid", client)
	c.Assert(err, qt.IsNil)
	ai, err := dc.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Assert(err, qt.IsNil)
	c.Assert(ai.Identity.Id(), qt.Equals, string(auth.AdminProviderID))

	id, ok := ai.Identity.(candidclient.Identity)
	c.Assert(ok, qt.Equals, true)
	username, err := id.Username()
	c.Assert(err, qt.IsNil)
	c.Assert(username, qt.Equals, auth.AdminUsername)
}
