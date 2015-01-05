// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"errors"
	"net/http/httptest"
	"net/url"

	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v0/bakery"
	"gopkg.in/macaroon-bakery.v0/bakery/checkers"
	"gopkg.in/macaroon-bakery.v0/httpbakery"
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
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: s.locator,
	})
	c.Assert(err, gc.IsNil)
	m, err := svc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  s.netSrv.URL + "/v1/discharge/",
		Condition: "test-condition",
	}})
	c.Assert(err, gc.IsNil)
	ms, err := httpbakery.DischargeAll(m, httpbakery.DefaultHTTPClient, noVisit)
	c.Assert(err, gc.IsNil)
	err = svc.Check(ms, never)
	c.Assert(err, gc.IsNil)
}

func noVisit(*url.URL) error {
	return errors.New("unexpected call to visit")
}

var never = bakery.FirstPartyCheckerFunc(func(string) error {
	return errors.New("unexpected first party caveat")
})
