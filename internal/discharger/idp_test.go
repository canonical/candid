// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger_test

import (
	"context"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	errgo "gopkg.in/errgo.v1"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/internal/auth"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/internal/discharger"
	"github.com/canonical/candid/internal/identity"
	"github.com/canonical/candid/internal/monitoring"
	"github.com/canonical/candid/meeting"
	"github.com/canonical/candid/params"
	"github.com/canonical/candid/store"
)

func TestIDP(t *testing.T) {
	qtsuite.Run(qt.New(t), &idpSuite{})
}

type idpSuite struct {
	store *candidtest.Store

	// template is used to configure the output generated by success
	// following a login. if there is a template called "login" in
	// template then it will be processed and the output returned.
	template     *template.Template
	meetingPlace *meeting.Place

	vc idp.VisitCompleter
}

func (s *idpSuite) Init(c *qt.C) {
	s.store = candidtest.NewStore()

	s.template = template.New("")

	oven := bakery.NewOven(bakery.OvenParams{
		Namespace: auth.Namespace,
		RootKeyStoreForOps: func([]bakery.Op) bakery.RootKeyStore {
			return s.store.BakeryRootKeyStore
		},
		Key:      bakery.MustGenerateKey(),
		Location: "candidtest",
	})
	var err error
	s.meetingPlace, err = meeting.NewPlace(meeting.Params{
		Store:      s.store.MeetingStore,
		Metrics:    monitoring.NewMeetingMetrics(),
		ListenAddr: "localhost",
	})
	c.Assert(err, qt.IsNil)
	c.Defer(s.meetingPlace.Close)

	kvs, err := s.store.ProviderDataStore.KeyValueStore(context.Background(), "test-discharge-tokens")
	c.Assert(err, qt.IsNil)
	s.vc = discharger.NewVisitCompleter(identity.HandlerParams{
		ServerParams: identity.ServerParams{
			Store:        s.store.Store,
			MeetingStore: s.store.MeetingStore,
			RootKeyStore: s.store.BakeryRootKeyStore,
			Template:     s.template,
			RedirectLoginTrustedURLs: []string{
				"http://example.com/callback",
			},
			RedirectLoginTrustedDomains: []string{
				"www.example.net",
				"*.example.org",
			},
		},
		MeetingPlace: s.meetingPlace,
		Oven:         oven,
	}, kvs, s.store.Store)
}

func (s *idpSuite) TestLoginFailure(c *qt.C) {
	rr := httptest.NewRecorder()
	s.vc.Failure(context.Background(), rr, nil, "", errgo.WithCausef(nil, params.ErrForbidden, "test error"))
	c.Assert(rr.Code, qt.Equals, http.StatusForbidden)
	var perr params.Error
	err := json.Unmarshal(rr.Body.Bytes(), &perr)
	c.Assert(err, qt.IsNil)
	c.Assert(perr, qt.DeepEquals, params.Error{
		Code:    params.ErrForbidden,
		Message: "test error",
	})
}

func (s *idpSuite) TestLoginFailureWithWait(c *qt.C) {
	id := "test"
	err := s.meetingPlace.NewRendezvous(context.Background(), id, []byte("test"))
	c.Assert(err, qt.IsNil)

	rr := httptest.NewRecorder()
	s.vc.Failure(context.Background(), rr, nil, id, errgo.WithCausef(nil, params.ErrForbidden, "test error"))
	c.Assert(rr.Code, qt.Equals, http.StatusForbidden)
	var perr params.Error
	err = json.Unmarshal(rr.Body.Bytes(), &perr)
	c.Assert(err, qt.IsNil)
	c.Assert(perr, qt.DeepEquals, params.Error{
		Code:    params.ErrForbidden,
		Message: "test error",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	d1, d2, err := s.meetingPlace.Wait(ctx, id)
	c.Assert(err, qt.IsNil)
	c.Assert(string(d1), qt.Equals, "test")
	var li discharger.LoginInfo
	err = json.Unmarshal(d2, &li)
	c.Assert(err, qt.IsNil)
	c.Assert(li.ProviderID, qt.Equals, store.ProviderIdentity(""))
	c.Assert(li.Error.Message, qt.Equals, "test error")
}

func (s *idpSuite) TestLoginSuccess(c *qt.C) {
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.vc.Success(context.Background(), rr, req, "", &store.Identity{
		Username: "test-user",
	})
	c.Assert(rr.Code, qt.Equals, http.StatusOK)
	c.Assert(rr.HeaderMap.Get("Content-Type"), qt.Equals, "text/plain; charset=utf-8")
	c.Assert(rr.Body.String(), qt.Equals, "Login successful as test-user")
}

func (s *idpSuite) TestLoginSuccessWithTemplate(c *qt.C) {
	_, err := s.template.New("login").Parse("<h1>Login successful as {{.Username}}</h1>")
	c.Assert(err, qt.IsNil)
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.vc.Success(context.Background(), rr, req, "", &store.Identity{
		Username: "test-user",
	})
	c.Assert(rr.Code, qt.Equals, http.StatusOK)
	c.Assert(rr.HeaderMap.Get("Content-Type"), qt.Equals, "text/html;charset=utf-8")
	c.Assert(rr.Body.String(), qt.Equals, "<h1>Login successful as test-user</h1>")
}

func (s *idpSuite) TestLoginRedirectSuccess(c *qt.C) {
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.vc.RedirectSuccess(context.Background(), rr, req, "http://example.com/callback", "1234", &store.Identity{
		Username: "test-user",
	})
	resp := rr.Result()
	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, qt.IsNil)
	c.Assert(resp.StatusCode, qt.Equals, http.StatusSeeOther, qt.Commentf("%s", body))
	loc, err := resp.Location()
	c.Assert(err, qt.IsNil)
	v := loc.Query()
	loc.RawQuery = ""
	c.Assert(loc.String(), qt.Equals, "http://example.com/callback")
	c.Assert(v.Get("state"), qt.Equals, "1234")
	c.Assert(v.Get("code"), qt.Not(qt.Equals), "")
}

func (s *idpSuite) TestLoginRedirectSuccessInvalidReturnTo(c *qt.C) {
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.vc.RedirectSuccess(context.Background(), rr, req, "::", "1234", &store.Identity{
		Username: "test-user",
	})
	c.Assert(rr.Code, qt.Equals, http.StatusBadRequest)
	var perr params.Error
	err = json.Unmarshal(rr.Body.Bytes(), &perr)
	c.Assert(err, qt.IsNil)
	c.Assert(perr, qt.DeepEquals, params.Error{
		Code:    params.ErrBadRequest,
		Message: `invalid return_to "::": parse "::": missing protocol scheme`,
	})
}

func (s *idpSuite) TestLoginRedirectSuccessReturnToNotTrusted(c *qt.C) {
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.vc.RedirectSuccess(context.Background(), rr, req, "https://example.com", "1234", &store.Identity{
		Username: "test-user",
	})
	c.Assert(rr.Code, qt.Equals, http.StatusBadRequest)
	var perr params.Error
	err = json.Unmarshal(rr.Body.Bytes(), &perr)
	c.Assert(err, qt.IsNil)
	c.Assert(perr, qt.DeepEquals, params.Error{
		Code:    params.ErrBadRequest,
		Message: `invalid return_to "https://example.com"`,
	})
}

func (s *idpSuite) TestLoginRedirectSuccessReturnToTrustedDomain(c *qt.C) {
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.vc.RedirectSuccess(context.Background(), rr, req, "https://www.example.net/callback/path", "1234", &store.Identity{
		Username: "test-user",
	})
	resp := rr.Result()
	c.Assert(resp.StatusCode, qt.Equals, http.StatusSeeOther)
	loc, err := resp.Location()
	c.Assert(err, qt.IsNil)
	v := loc.Query()
	loc.RawQuery = ""
	c.Assert(loc.String(), qt.Equals, "https://www.example.net/callback/path")
	c.Assert(v.Get("state"), qt.Equals, "1234")
	c.Assert(v.Get("code"), qt.Not(qt.Equals), "")
}

func (s *idpSuite) TestLoginRedirectSuccessReturnToTrustedDomainWildcard(c *qt.C) {
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.vc.RedirectSuccess(context.Background(), rr, req, "https://my.host.example.org/callback/path", "1234", &store.Identity{
		Username: "test-user",
	})
	resp := rr.Result()
	c.Assert(resp.StatusCode, qt.Equals, http.StatusSeeOther)
	loc, err := resp.Location()
	c.Assert(err, qt.IsNil)
	v := loc.Query()
	loc.RawQuery = ""
	c.Assert(loc.String(), qt.Equals, "https://my.host.example.org/callback/path")
	c.Assert(v.Get("state"), qt.Equals, "1234")
	c.Assert(v.Get("code"), qt.Not(qt.Equals), "")
}

func (s *idpSuite) TestLoginRedirectSuccessReturnToTrustedDomainInsecure(c *qt.C) {
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.vc.RedirectSuccess(context.Background(), rr, req, "http://www.example.net/callback/path", "1234", &store.Identity{
		Username: "test-user",
	})
	c.Assert(rr.Code, qt.Equals, http.StatusBadRequest)
	var perr params.Error
	err = json.Unmarshal(rr.Body.Bytes(), &perr)
	c.Assert(err, qt.IsNil)
	c.Assert(perr, qt.DeepEquals, params.Error{
		Code:    params.ErrBadRequest,
		Message: `invalid return_to "http://www.example.net/callback/path"`,
	})
}

func (s *idpSuite) TestLoginRedirectFailureInvalidReturnTo(c *qt.C) {
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.vc.RedirectFailure(context.Background(), rr, req, "::", "1234", errgo.WithCausef(nil, params.ErrForbidden, "test error"))
	c.Assert(rr.Code, qt.Equals, http.StatusForbidden)
	var perr params.Error
	err = json.Unmarshal(rr.Body.Bytes(), &perr)
	c.Assert(err, qt.IsNil)
	c.Assert(perr, qt.DeepEquals, params.Error{
		Code:    params.ErrForbidden,
		Message: `test error`,
	})
}
