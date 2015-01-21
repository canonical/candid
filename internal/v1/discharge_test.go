// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v0/bakery"
	"gopkg.in/macaroon-bakery.v0/bakery/checkers"
	"gopkg.in/macaroon-bakery.v0/httpbakery"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/params"
)

type dischargeSuite struct {
	apiSuite
	locator *bakery.PublicKeyRing
	netSrv  *httptest.Server
}

var _ = gc.Suite(&dischargeSuite{})

func (s *dischargeSuite) SetUpTest(c *gc.C) {
	s.apiSuite.SetUpTest(c)
	s.locator = bakery.NewPublicKeyRing()
	s.netSrv = httptest.NewServer(s.srv)
	s.locator.AddPublicKeyForLocation(s.netSrv.URL, true, s.key)
}

func (s *dischargeSuite) TearDownTest(c *gc.C) {
	s.netSrv.Close()
	s.apiSuite.TearDownTest(c)
}

func (s *dischargeSuite) TestDischarge(c *gc.C) {
	s.createUser(c, &params.User{
		UserName:   "jbloggs",
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
			Location:  s.netSrv.URL + "/v1/discharge/",
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
			Location:  s.netSrv.URL + "/v1/discharge/",
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
			Location:  s.netSrv.URL + "/v1/discharge/",
			Condition: "is-authenticated-user",
		}}),
		modifier: &requestModifier{
			f: func(r *http.Request) {
				r.URL.RawQuery += "&discharge-for-user=jbloggs"
			},
		},
		expectErr: ".*cannot discharge: unauthorized: unauthorized: invalid or missing HTTP auth header",
	}, {
		about: "unsupported user",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  s.netSrv.URL + "/v1/discharge/",
			Condition: "is-authenticated-user",
		}}),
		modifier: &requestModifier{
			f: func(r *http.Request) {
				r.SetBasicAuth(adminUsername, adminPassword)
				r.URL.RawQuery += "&discharge-for-user=jbloggs2"
			},
		},
		expectErr: `.*cannot discharge: user "jbloggs2" not found: not found`,
	}, {
		about: "unsupported condition",
		m: newMacaroon(c, svc, []checkers.Caveat{{
			Location:  s.netSrv.URL + "/v1/discharge/",
			Condition: "is-authenticated-group",
		}}),
		modifier: &requestModifier{
			f: func(r *http.Request) {
				r.SetBasicAuth(adminUsername, adminPassword)
				r.Header.Add("X-Discharge-For-Username", "jbloggs2")
			},
		},
		expectErr: `.*caveat not recognized`,
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		client := httpbakery.NewHTTPClient()
		if test.modifier != nil {
			test.modifier.transport = client.Transport
			client.Transport = test.modifier
		}
		ms, err := httpbakery.DischargeAll(test.m, client, noVisit)
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

func noVisit(*url.URL) error {
	return errors.New("unexpected call to visit")
}

var never = bakery.FirstPartyCheckerFunc(func(string) error {
	return errors.New("unexpected first party caveat")
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

func (s *dischargeSuite) createUser(c *gc.C, user *params.User) {
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/" + user.UserName),
		Method:  "PUT",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:         marshal(c, user),
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
		ExpectBody:   user,
	})
}
