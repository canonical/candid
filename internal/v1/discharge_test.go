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
	"path"
	"strings"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/httptesting"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent"
	"gopkg.in/macaroon.v2-unstable"

	"github.com/CanonicalLtd/blues-identity/idp"
	agentidp "github.com/CanonicalLtd/blues-identity/idp/agent"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/test"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/internal/v1"
)

var groupOp = bakery.Op{"group", "group"}

var testContext = context.Background()

type dischargeSuite struct {
	idptest.DischargeSuite
	user *params.User
	// bakery holds a bakery that represents a target
	// service that can issue macaroons.
	bakery *bakery.Bakery
}

var _ = gc.Suite(&dischargeSuite{})

func (s *dischargeSuite) SetUpTest(c *gc.C) {
	s.IDPs = []idp.IdentityProvider{
		test.NewIdentityProvider(test.Params{Name: "test"}),
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
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.bakery = bakery.New(bakery.BakeryParams{
		Locator:        s.Locator,
		Key:            key,
		IdentityClient: idptest.IdentityClient{},
	})
}

func (s *dischargeSuite) TestInteractiveDischarge(c *gc.C) {
	visitor := &test.Visitor{
		User: s.user,
	}
	s.AssertDischarge(c, visitor)
}

func (s *dischargeSuite) TestNonInteractiveDischarge(c *gc.C) {
	visitor := &test.Visitor{
		User: s.user,
	}
	s.AssertDischarge(c, httpbakery.NewMultiVisitor(visitor))
}

func (s *dischargeSuite) TestDischargeUsernameLookup(c *gc.C) {
	err := s.IDMClient.SetUser(testContext, &params.SetUserRequest{
		Username: s.user.Username,
		User:     *s.user,
	})
	c.Assert(err, gc.IsNil)
	visitor := &test.Visitor{
		User: &params.User{
			Username: s.user.Username,
		},
	}
	s.AssertDischarge(c, visitor)
}

func (s *dischargeSuite) TestDischargeExternalIDLookup(c *gc.C) {
	err := s.IDMClient.SetUser(testContext, &params.SetUserRequest{
		Username: s.user.Username,
		User:     *s.user,
	})
	c.Assert(err, gc.IsNil)
	visitor := &test.Visitor{
		User: &params.User{
			ExternalID: s.user.ExternalID,
		},
	}
	s.AssertDischarge(c, visitor)
}

func (s *dischargeSuite) TestDischargeWhenLoggedIn(c *gc.C) {
	visitor := &test.Visitor{
		User: s.user,
	}
	s.AssertDischarge(c, visitor)
	s.AssertDischarge(c, noVisit)

	// Check that we cannot do the same when we're
	// making the requests from a different origin.
	s.AssertDischarge(c, noVisit)
}

func (s *dischargeSuite) TestWaitReturnsDischargeToken(c *gc.C) {
	visitor := &test.Visitor{
		User: s.user,
	}
	transport := &responseBodyRecordingTransport{
		c:         c,
		transport: s.BakeryClient.Transport,
	}
	s.BakeryClient.Transport = transport
	s.AssertDischarge(c, visitor)

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

func (s *dischargeSuite) TestVisitURLWithDomainCookie(c *gc.C) {
	u, err := url.Parse("https://idp.test/discharge")
	c.Assert(err, gc.Equals, nil)
	s.BakeryClient.Client.Jar.SetCookies(u, []*http.Cookie{{
		Name:  "domain",
		Value: "test2",
	}})
	visitor := &valueSavingVisitor{
		visitor: &test.Visitor{
			User: s.user,
		},
	}
	s.AssertDischarge(c, visitor)
	c.Assert(visitor.url.Query().Get("domain"), gc.Equals, "test2")
}

func (s *dischargeSuite) TestVisitURLWithInvalidDomainCookie(c *gc.C) {
	u, err := url.Parse("https://idp.test/discharge")
	c.Assert(err, gc.Equals, nil)
	s.BakeryClient.Client.Jar.SetCookies(u, []*http.Cookie{{
		Name:  "domain",
		Value: "test2-",
	}})
	visitor := &valueSavingVisitor{
		visitor: &test.Visitor{
			User: s.user,
		},
	}
	s.AssertDischarge(c, visitor)
	c.Assert(visitor.url.Query().Get("domain"), gc.Equals, "")
}

func (s *dischargeSuite) TestVisitURLWithEscapedDomainCookie(c *gc.C) {
	u, err := url.Parse("https://idp.test/discharge")
	c.Assert(err, gc.Equals, nil)
	s.BakeryClient.Client.Jar.SetCookies(u, []*http.Cookie{{
		Name:  "domain",
		Value: "test+2",
	}})
	visitor := &valueSavingVisitor{
		visitor: &test.Visitor{
			User: s.user,
		},
	}
	s.AssertDischarge(c, visitor)
	c.Assert(visitor.url.Query().Get("domain"), gc.Equals, "test+2")
}

type valueSavingVisitor struct {
	url     *url.URL
	visitor httpbakery.Visitor
}

func (v *valueSavingVisitor) VisitWebPage(ctx context.Context, client *httpbakery.Client, methodURLs map[string]*url.URL) error {
	v.url = methodURLs[httpbakery.UserInteractionMethod]
	return v.visitor.VisitWebPage(ctx, client, methodURLs)
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
	visitor := &test.Visitor{
		User: s.user,
	}
	s.AssertDischarge(c, visitor)
	s.AssertDischarge(c, noVisit)

	// Check that we can't discharge using the idm macaroon
	// when we've got a different origin header.
	m := s.newMacaroon("is-authenticated-user", bakery.LoginOp)
	s.BakeryClient.WebPageVisitor = noVisit
	s.BakeryClient.Transport = originTransport{s.BakeryClient.Transport, "somewhere"}
	_, err := s.BakeryClient.DischargeAll(testContext, m)
	// TODO this error doesn't seem that closely related to the test failure condition.
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

var noVisit = noVisitor{}

type noVisitor struct{}

func (noVisitor) VisitWebPage(context.Context, *httpbakery.Client, map[string]*url.URL) error {
	return errors.New("unexpected call to visit")
}

func (s *dischargeSuite) TestDischargeAgentShortcut(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	err = s.IDMClient.SetUser(
		testContext,
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
	agentSetUpAuth(s.BakeryClient, "testagent@admin@idm")

	s.AssertDischarge(c, nil)

}

func agentSetUpAuth(c *httpbakery.Client, agentName string) {
	var v agent.Visitor
	err := v.AddAgent(agent.Agent{
		URL:      idptest.DischargeLocation,
		Username: agentName,
		Key:      c.Key,
	})
	if err != nil {
		panic(err)
	}
	c.WebPageVisitor = &v
}

func (s *dischargeSuite) TestAdminDischargeTokenForUserNotFound(c *gc.C) {
	req, err := http.NewRequest("GET", idptest.DischargeLocation+"/v1/discharge-token-for-user?username=jbloggs", nil)
	req.SetBasicAuth(adminUsername, adminPassword)
	resp, err := s.HTTPClient.Do(req)
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusNotFound)
}

func (s *dischargeSuite) TestAdminDischargeTokenForUserNoUser(c *gc.C) {
	req, err := http.NewRequest("GET", idptest.DischargeLocation+"/v1/discharge-token-for-user", nil)
	req.SetBasicAuth(adminUsername, adminPassword)
	resp, err := s.HTTPClient.Do(req)
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusBadRequest)
}

func (s *dischargeSuite) TestAdminDischargeTokenForUserNotAdmin(c *gc.C) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Do:          s.BakeryClient.Do,
		URL:         idptest.DischargeLocation + "/v1/discharge-token-for-user?username=jbloggs",
		ExpectError: `cannot get discharge from "https://idp.test": cannot start interactive session: interaction required but not possible`,
	})
}

func (s *dischargeSuite) TestAdminDischargeTokenForUser(c *gc.C) {
	err := s.IDMClient.SetUser(
		testContext,
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
	req, err := http.NewRequest("GET", idptest.DischargeLocation+"/v1/discharge-token-for-user?username=jbloggs", nil)
	req.SetBasicAuth(adminUsername, adminPassword)
	resp, err := s.HTTPClient.Do(req)
	c.Assert(err, gc.IsNil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, gc.IsNil)
	var data v1.DischargeTokenForUserResponse
	err = json.Unmarshal(body, &data)
	c.Assert(err, gc.IsNil)
	// TODO actually check macaroon directly.
	decl := checkers.InferDeclared(nil, macaroon.Slice{data.DischargeToken.M()})
	c.Assert(decl, jc.DeepEquals, map[string]string{
		"username": "jbloggs",
	})
}

func (s *dischargeSuite) TestDischargeForUser(c *gc.C) {
	err := s.IDMClient.SetUser(
		testContext,
		&params.SetUserRequest{
			Username: "jbloggs",
			User: params.User{
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
	err = s.IDMClient.SetUser(
		testContext,
		&params.SetUserRequest{
			Username: "jbloggs@test",
			User: params.User{
				ExternalID: "http://test.example.com/jbloggs",
				Email:      "jbloggs@test.example.com",
				FullName:   "Joe Bloggs",
				IDPGroups: []string{
					"test",
				},
			},
		},
	)
	c.Assert(err, gc.IsNil)
	tests := []struct {
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
		username:         adminUsername,
		password:         adminPassword,
		dischargeForUser: "jbloggs",
		expectUser:       "jbloggs",
	}, {
		about:     "no discharge user",
		condition: "is-authenticated-user",
		username:  adminUsername,
		password:  adminPassword,
		// Without the discharge-for-user query parameter, the administrator
		// is just discharging for themselves.
		// Note that even though we've used "admin" as the basic-auth
		// user name, the identity server treats it the same
		// as if it had agent authenticated as the admin agent.
		expectUser: store.AdminUsername,
	}, {
		about:            "no authentication",
		condition:        "is-authenticated-user",
		dischargeForUser: "jbloggs",
		expectErr:        `cannot get discharge from "https://idp.test": Post https://idp.test/discharge: cannot get discharge from "https://idp.test": cannot start interactive session: interaction required but not possible`,
	}, {
		about:            "unsupported user",
		condition:        "is-authenticated-user",
		username:         adminUsername,
		password:         adminPassword,
		dischargeForUser: "jbloggs2",
		expectErr:        `cannot get discharge from "https://idp.test": Post https://idp.test/discharge: cannot discharge: invalid username "jbloggs2": user "jbloggs2" not found: not found`,
	}, {
		about:            "unsupported condition",
		condition:        "is-authenticated-group",
		username:         adminUsername,
		password:         adminPassword,
		dischargeForUser: "jbloggs",
		expectErr:        `.*caveat not recognized`,
	}, {
		about:            "bad credentials",
		condition:        "is-authenticated-user",
		username:         "not-admin-username",
		password:         adminPassword,
		dischargeForUser: "jbloggs",
		expectErr:        `cannot get discharge from "https://idp.test": Post https://idp.test/discharge: cannot discharge: could not determine identity: invalid credentials`,
	}, {
		about:            "is-authenticated-user with domain",
		condition:        "is-authenticated-user @test",
		username:         adminUsername,
		password:         adminPassword,
		dischargeForUser: "jbloggs@test",
		expectUser:       "jbloggs@test",
	}, {
		about:            "is-authenticated-user with wrong domain",
		condition:        "is-authenticated-user @test2",
		username:         adminUsername,
		password:         adminPassword,
		dischargeForUser: "jbloggs@test",
		expectErr:        `cannot get discharge from "https://idp.test": Post https://idp.test/discharge: cannot discharge: invalid username "jbloggs@test": "jbloggs@test" not in required domain "test2"`,
	}, {
		about:            "is-authenticated-user with invalid domain",
		condition:        "is-authenticated-user @test-",
		username:         adminUsername,
		password:         adminPassword,
		dischargeForUser: "jbloggs@test",
		expectErr:        `cannot get discharge from "https://idp.test": Post https://idp.test/discharge: cannot discharge: invalid domain "test-"`,
	}, {
		about:            "invalid caveat",
		condition:        " invalid caveat",
		username:         adminUsername,
		password:         adminPassword,
		dischargeForUser: "jbloggs@test",
		expectErr:        `cannot get discharge from "https://idp.test": Post https://idp.test/discharge: cannot discharge: cannot parse caveat " invalid caveat": caveat starts with space character`,
	}}
	for i, test := range tests {
		c.Logf("test %d. %s", i, test.about)
		cl0 := httpbakery.NewClient()
		cl0.Transport = s.RoundTripper
		da := &testDischargeAcquirer{
			client:           &httprequest.Client{Doer: cl0},
			username:         test.username,
			password:         test.password,
			dischargeForUser: test.dischargeForUser,
		}

		client := httpbakery.NewClient()
		client.Transport = s.RoundTripper
		client.DischargeAcquirer = da

		m := s.newMacaroon(test.condition, bakery.LoginOp)
		ms, err := client.DischargeAll(testContext, m)

		if test.expectErr != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErr)
			continue
		}
		c.Assert(err, gc.IsNil)
		s.assertDischarged(c, ms, bakery.LoginOp, test.expectUser)
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

// newMacaroon uses s.bakery to mint a new macaroon for the third party caveat condition
// and operation.
func (s *dischargeSuite) newMacaroon(thirdPartyCondition string, op bakery.Op) *bakery.Macaroon {
	m, err := s.bakery.Oven.NewMacaroon(
		testContext,
		bakery.LatestVersion,
		time.Now().Add(time.Minute),
		[]checkers.Caveat{{
			Location:  idptest.DischargeLocation,
			Condition: thirdPartyCondition,
		}},
		op,
	)
	if err != nil {
		panic(err)
	}
	return m
}

// assertDischarged asserts that the given macaroon slice
// is valid the given operation with respect to s.bakery.
//
// If user is non-empty, it is expected that the
// discharge macaroon will have declared the given username,
// otherwise no identity should have been declared.
func (s dischargeSuite) assertDischarged(c *gc.C, ms macaroon.Slice, op bakery.Op, user string) {
	authInfo, err := s.bakery.Checker.Auth(ms).Allow(testContext, op)
	c.Assert(err, gc.IsNil)
	if user != "" {
		c.Assert(authInfo.Identity.Id(), gc.Equals, user)
	} else {
		c.Assert(authInfo.Identity, gc.Equals, nil)
	}
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
	visitor := test.Visitor{
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
	s.BakeryClient.WebPageVisitor = visitor

	tests := []struct {
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
		expectError: "third party refused discharge: user is not a member of required groups",
	}, {
		about:     "test membership in a set of groups - one group matches",
		condition: "is-member-of test2 test4",
	}, {
		about:       "test membership in a set of groups fail - no match",
		condition:   "is-member-of test1 test3",
		expectError: "third party refused discharge: user is not a member of required groups",
	},
	}

	for i, test := range tests {
		c.Logf("%d. %q", i, test.about)
		m := s.newMacaroon(test.condition, groupOp)
		ms, err := s.BakeryClient.DischargeAll(testContext, m)
		if test.expectError != "" {
			c.Assert(errgo.Cause(err), gc.ErrorMatches, test.expectError)
		} else {
			c.Assert(err, gc.IsNil)
			s.assertDischarged(c, ms, groupOp, "")
		}
	}
}

func (s *dischargeSuite) TestDischargeXMemberOfX(c *gc.C) {
	// if the user is X member of no group, we must still
	// discharge is-member-of X.
	visitor := test.Visitor{
		User: &params.User{
			Username:   "test-user",
			ExternalID: "http://example.com/test-user",
			Email:      "test-user@example.com",
			FullName:   "Test User III",
			IDPGroups:  []string{},
		},
	}
	s.BakeryClient.WebPageVisitor = visitor

	m := s.newMacaroon("is-member-of test-user", groupOp)
	ms, err := s.BakeryClient.DischargeAll(testContext, m)
	c.Assert(err, gc.IsNil)
	s.assertDischarged(c, ms, groupOp, "")
}

// This test is not sending the bakery protocol version so it will use the default
// one and return a 407.
func (s *dischargeSuite) TestDischargeStatusProxyAuthRequiredResponse(c *gc.C) {
	// Make a version 1 macaroon so that the caveat is in the macaroon
	// and it's appropriate for a 407-era macaroon.
	m, err := s.bakery.Oven.NewMacaroon(
		testContext,
		bakery.Version1,
		time.Now().Add(time.Minute),
		[]checkers.Caveat{{
			Location:  idptest.DischargeLocation,
			Condition: "is-authenticated-user",
		}},
		bakery.LoginOp,
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
	resp, err := s.HTTPClient.PostForm(idptest.DischargeLocation+"/discharge", url.Values{
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
	m, err := s.bakery.Oven.NewMacaroon(
		testContext,
		bakery.Version2,
		time.Now().Add(time.Minute),
		[]checkers.Caveat{{
			Location:  idptest.DischargeLocation,
			Condition: "is-authenticated-user",
		}},
		bakery.LoginOp,
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
	visitor := &test.Visitor{
		User: s.user,
	}
	s.BakeryClient.WebPageVisitor = visitor
	m := s.newMacaroon("is-authenticated-user", bakery.LoginOp)
	ms, err := s.BakeryClient.DischargeAll(testContext, m)
	c.Assert(err, gc.IsNil)
	s.assertDischarged(c, ms, bakery.LoginOp, "test")
}

func (s *dischargeSuite) TestPublicKeyLegacyLocation(c *gc.C) {
	info, err := s.Locator.ThirdPartyInfo(testContext, idptest.DischargeLocation)
	c.Assert(err, gc.IsNil)
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		URL:          idptest.DischargeLocation + "/v1/discharger/publickey",
		Do:           s.HTTPClient.Do,
		ExpectStatus: http.StatusOK,
		ExpectBody: map[string]*bakery.PublicKey{
			"PublicKey": &info.PublicKey,
		},
	})
}

func (s *dischargeSuite) TestPublicKey(c *gc.C) {
	info, err := s.Locator.ThirdPartyInfo(testContext, idptest.DischargeLocation)
	c.Assert(err, gc.IsNil)
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		URL:          idptest.DischargeLocation + "/publickey",
		Do:           s.HTTPClient.Do,
		ExpectStatus: http.StatusOK,
		ExpectBody: map[string]*bakery.PublicKey{
			"PublicKey": &info.PublicKey,
		},
	})
}

func (s *dischargeSuite) TestIdentityCookieParameters(c *gc.C) {
	jar := new(testCookieJar)
	s.BakeryClient.Client.Jar = jar
	visitor := test.Visitor{
		User: s.user,
	}
	s.BakeryClient.WebPageVisitor = visitor
	m := s.newMacaroon("is-authenticated-user", bakery.LoginOp)

	ms, err := s.BakeryClient.DischargeAll(testContext, m)
	c.Assert(err, gc.IsNil)
	s.assertDischarged(c, ms, bakery.LoginOp, "test")
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
	visitor := &test.Visitor{
		User: s.user,
	}
	s.AssertDischarge(c, visitor)

	u1, err := s.IDMClient.User(
		testContext,
		&params.UserRequest{
			Username: s.user.Username,
		})
	c.Assert(err, gc.Equals, nil)
	c.Assert(u1.LastDischarge.IsZero(), gc.Equals, false)

	// Wait at least one ms so that the discharge time stored in the
	// database is necessarily different.
	time.Sleep(time.Millisecond)

	s.AssertDischarge(c, visitor)

	u2, err := s.IDMClient.User(testContext, &params.UserRequest{
		Username: s.user.Username,
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(u2.LastDischarge.After(*u1.LastDischarge), gc.Equals, true)
}

func (s *dischargeSuite) TestDomainInInteractionURLs(c *gc.C) {
	tests := []struct {
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
	for i, tst := range tests {
		c.Logf("test %d. %s", i, tst.about)
		client := httpbakery.NewClient()
		client.Transport = s.RoundTripper
		username := "user"
		if tst.expectDomain != "" {
			username = "user@" + tst.expectDomain
		}
		client.WebPageVisitor = &valueSavingVisitor{
			visitor: &test.Visitor{
				User: &params.User{
					Username:   params.Username(username),
					ExternalID: tst.expectDomain + ":user",
				},
			},
		}
		for k, v := range tst.cookies {
			u, err := url.Parse(idptest.DischargeLocation)
			c.Assert(err, gc.IsNil)
			client.Jar.SetCookies(u, []*http.Cookie{{
				Name:  k,
				Value: v,
			}})
		}
		m := s.newMacaroon(tst.condition, bakery.LoginOp)
		ms, err := client.DischargeAll(testContext, m)
		c.Assert(err, gc.IsNil)
		s.assertDischarged(c, ms, bakery.LoginOp, username)
	}
}

func (s *dischargeSuite) TestDischargeWithDomainWithExistingNonDomainAuth(c *gc.C) {
	// First log in successfully without a domain.
	s.AssertDischarge(c, &test.Visitor{
		&params.User{
			Username:   "bob",
			ExternalID: "bobexternal",
		},
	})
	// Then try with a caveat that requires a domain.
	b, ms, err := s.Discharge(c, "is-authenticated-user @somewhere", &test.Visitor{
		&params.User{
			Username:   "alice@somewhere",
			ExternalID: "aliceexternal",
		},
	})
	c.Assert(err, gc.Equals, nil)
	authInfo, err := b.Checker.Auth(ms).Allow(context.Background(), bakery.LoginOp)
	c.Assert(err, gc.IsNil)
	c.Assert(authInfo.Identity, gc.Not(gc.Equals), nil)
	c.Assert(authInfo.Identity.Id(), gc.Equals, "alice@somewhere")
}
