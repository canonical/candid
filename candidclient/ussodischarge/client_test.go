// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package ussodischarge_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon.v2"

	"github.com/canonical/candid/candidclient/ussodischarge"
	"github.com/canonical/candid/params"
)

var _ httpbakery.Interactor = (*ussodischarge.Interactor)(nil)
var _ httpbakery.LegacyInteractor = (*ussodischarge.Interactor)(nil)

var testContext = context.Background()

var macaroonEquals = qt.CmpEquals(cmp.AllowUnexported(macaroon.Macaroon{}), cmpopts.EquateEmpty())

func TestClient(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	qtsuite.Run(c, &clientSuite{})
}

type clientSuite struct {
	testMacaroon          *bakery.Macaroon
	testDischargeMacaroon *macaroon.Macaroon
	srv                   *httptest.Server

	// macaroon is returned from the /macaroon endpoint of the test server.
	// If this is nil, an error will be returned instead.
	macaroon *bakery.Macaroon
}

// ServeHTTP allows us to use the test suite as a handler to test the
// client methods against.
func (s *clientSuite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/macaroon":
		s.serveMacaroon(w, r)
	case "/login":
		s.serveLogin(w, r)
	case "/api/v2/tokens/discharge":
		s.serveDischarge(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *clientSuite) Init(c *qt.C) {
	var err error
	s.testMacaroon, err = bakery.NewMacaroon([]byte("test rootkey"), []byte("test macaroon"), "test location", bakery.LatestVersion, nil)
	c.Assert(err, qt.IsNil)
	// Discharge macaroons from Ubuntu SSO will be binary encoded in the version 1 format.
	s.testDischargeMacaroon, err = macaroon.New([]byte("test discharge rootkey"), []byte("test discharge macaroon"), "test discharge location", macaroon.V1)
	c.Assert(err, qt.IsNil)

	s.srv = httptest.NewServer(s)
	c.Defer(s.srv.Close)
	s.macaroon = nil
}

func (s *clientSuite) TestMacaroon(c *qt.C) {
	s.macaroon = s.testMacaroon
	m, err := ussodischarge.Macaroon(testContext, nil, s.srv.URL+"/macaroon")
	c.Assert(err, qt.IsNil)
	c.Assert(m.M(), macaroonEquals, s.testMacaroon.M())
}

func (s *clientSuite) TestMacaroonError(c *qt.C) {
	m, err := ussodischarge.Macaroon(testContext, nil, s.srv.URL+"/macaroon")
	c.Assert(m, qt.IsNil)
	c.Assert(err, qt.ErrorMatches, `cannot get macaroon: Get http.*: test error`)
}

func (s *clientSuite) TestVisitor(c *qt.C) {
	v := ussodischarge.NewInteractor(func(_ *httpbakery.Client, url string) (macaroon.Slice, error) {
		c.Assert(url, qt.Equals, s.srv.URL+"/login")
		return macaroon.Slice{s.testMacaroon.M()}, nil
	})

	client := httpbakery.NewClient()
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	ierr := httpbakery.NewInteractionRequiredError(nil, req)
	ussodischarge.SetInteraction(ierr, s.srv.URL+"/login")
	dt, err := v.Interact(testContext, client, "", ierr)
	c.Assert(err, qt.IsNil)
	c.Assert(dt, qt.DeepEquals, &httpbakery.DischargeToken{
		Kind:  "test-kind",
		Value: []byte("test-value"),
	})
}

func (s *clientSuite) TestVisitorMethodNotSupported(c *qt.C) {
	v := ussodischarge.NewInteractor(func(_ *httpbakery.Client, url string) (macaroon.Slice, error) {
		return nil, errgo.New("function called unexpectedly")
	})
	client := httpbakery.NewClient()
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	ierr := httpbakery.NewInteractionRequiredError(nil, req)
	ierr.SetInteraction("other", nil)
	dt, err := v.Interact(testContext, client, "", ierr)
	c.Assert(errgo.Cause(err), qt.Equals, httpbakery.ErrInteractionMethodNotFound)
	c.Assert(dt, qt.IsNil)
}

func (s *clientSuite) TestVisitorFunctionError(c *qt.C) {
	v := ussodischarge.NewInteractor(func(_ *httpbakery.Client, url string) (macaroon.Slice, error) {
		return nil, errgo.WithCausef(nil, testCause, "test error")
	})
	client := httpbakery.NewClient()
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	ierr := httpbakery.NewInteractionRequiredError(nil, req)
	ussodischarge.SetInteraction(ierr, s.srv.URL+"/login")
	dt, err := v.Interact(testContext, client, "", ierr)
	c.Assert(errgo.Cause(err), qt.Equals, testCause)
	c.Assert(err, qt.ErrorMatches, "test error")
	c.Assert(dt, qt.IsNil)
}

func (s *clientSuite) TestAcquireDischarge(c *qt.C) {
	d := &ussodischarge.Discharger{
		Email:    "user@example.com",
		Password: "secret",
		OTP:      "123456",
	}
	m, err := d.AcquireDischarge(testContext, macaroon.Caveat{
		Location: s.srv.URL,
		Id:       []byte("test caveat id"),
	}, nil)
	c.Assert(err, qt.IsNil)
	c.Assert(m.M(), macaroonEquals, s.testDischargeMacaroon)
}

func (s *clientSuite) TestAcquireDischargeError(c *qt.C) {
	d := &ussodischarge.Discharger{
		Email:    "user@example.com",
		Password: "bad-secret",
		OTP:      "123456",
	}
	m, err := d.AcquireDischarge(testContext, macaroon.Caveat{
		Location: s.srv.URL,
		Id:       []byte("test caveat id"),
	}, nil)
	c.Assert(err, qt.ErrorMatches, `Post http.*: Provided email/password is not correct.`)
	c.Assert(m, qt.IsNil)
}

func (s *clientSuite) TestDischargeAll(c *qt.C) {
	m := s.testMacaroon.Clone()
	err := m.M().AddThirdPartyCaveat([]byte("third party root key"), []byte("third party caveat id"), s.srv.URL)
	c.Assert(err, qt.IsNil)
	d := &ussodischarge.Discharger{
		Email:    "user@example.com",
		Password: "secret",
		OTP:      "123456",
	}
	ms, err := d.DischargeAll(testContext, m)
	c.Assert(err, qt.IsNil)
	md := s.testDischargeMacaroon.Clone()
	md.Bind(m.M().Signature())
	c.Assert(ms, macaroonEquals, macaroon.Slice{m.M(), md})
}

func (s *clientSuite) TestDischargeAllError(c *qt.C) {
	m := s.testMacaroon.Clone()
	err := m.M().AddThirdPartyCaveat([]byte("third party root key"), []byte("third party caveat id"), s.srv.URL)
	c.Assert(err, qt.IsNil)
	d := &ussodischarge.Discharger{
		Email:    "user@example.com",
		Password: "bad-secret",
		OTP:      "123456",
	}
	ms, err := d.DischargeAll(testContext, m)
	c.Assert(err, qt.ErrorMatches, `cannot get discharge from ".*": Post http.*: Provided email/password is not correct.`)
	c.Assert(ms, qt.IsNil)
}

func (s *clientSuite) serveMacaroon(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, r, errgo.Newf("bad method: %s", r.Method))
	}
	if s.macaroon != nil {
		httprequest.WriteJSON(w, http.StatusOK, ussodischarge.MacaroonResponse{
			Macaroon: s.macaroon,
		})
	} else {
		httprequest.WriteJSON(w, http.StatusInternalServerError, params.Error{
			Message: "test error",
		})
	}
}

func (s *clientSuite) serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, r, errgo.Newf("bad method: %s", r.Method))
	}
	var lr ussodischarge.LoginRequest
	if err := httprequest.Unmarshal(httprequest.Params{Request: r, Response: w}, &lr); err != nil {
		fail(w, r, err)
	}
	if n := len(lr.Login.Macaroons); n != 1 {
		fail(w, r, errgo.Newf("macaroon slice has unexpected length %d", n))
	}
	if id := lr.Login.Macaroons[0].Id(); string(id) != "test macaroon" {
		fail(w, r, errgo.Newf("unexpected macaroon sent %q", string(id)))
	}
	httprequest.WriteJSON(w, http.StatusOK, ussodischarge.LoginResponse{
		DischargeToken: &httpbakery.DischargeToken{
			Kind:  "test-kind",
			Value: []byte("test-value"),
		},
	})
}

func (s *clientSuite) serveDischarge(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, r, errgo.Newf("bad method: %s", r.Method))
	}
	var dr ussodischarge.USSODischargeRequest
	if err := httprequest.Unmarshal(httprequest.Params{Request: r, Response: w}, &dr); err != nil {
		fail(w, r, err)
	}
	if dr.Discharge.Email == "" {
		fail(w, r, errgo.New("email not specified"))
	}
	if dr.Discharge.Password == "" {
		fail(w, r, errgo.New("password not specified"))
	}
	if dr.Discharge.OTP == "" {
		fail(w, r, errgo.New("otp not specified"))
	}
	if dr.Discharge.CaveatID == "" {
		fail(w, r, errgo.New("caveat_id not specified"))
	}
	if dr.Discharge.Email != "user@example.com" || dr.Discharge.Password != "secret" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error_list": [{"message": "Provided email/password is not correct.", "code": "invalid-credentials"}], "message": "Provided email/password is not correct.", "code": "INVALID_CREDENTIALS", "extra": {}}`))
		return
	}
	var m ussodischarge.USSOMacaroon
	m.Macaroon = *s.testDischargeMacaroon
	httprequest.WriteJSON(w, http.StatusOK, map[string]interface{}{"discharge_macaroon": &m})
}

func fail(w http.ResponseWriter, r *http.Request, err error) {
	httprequest.WriteJSON(w, http.StatusBadRequest, params.Error{
		Message: err.Error(),
	})
}

var testCause = errgo.New("test cause")
