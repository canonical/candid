// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	qt "github.com/frankban/quicktest"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/candid/internal/candidtest"
	"github.com/CanonicalLtd/candid/internal/discharger"
	"github.com/CanonicalLtd/candid/internal/identity"
)

type agentSuite struct {
	srv              *candidtest.Server
	store            *candidtest.Store
	dischargeCreator *candidtest.DischargeCreator
}

func (s *agentSuite) Init(c *qt.C) {
	s.srv = candidtest.NewMemServer(c, map[string]identity.NewAPIHandlerFunc{
		"discharger": discharger.NewAPIHandler,
	})
	s.dischargeCreator = candidtest.NewDischargeCreator(s.srv)
}

func (s *agentSuite) TestHTTPBakeryAgentDischarge(c *qt.C) {
	key := s.srv.CreateAgent(c, "bob@candid")
	client := s.srv.Client(nil)
	client.Key = key
	err := agent.SetUpAuth(client, &agent.AuthInfo{
		Key: client.Key,
		Agents: []agent.Agent{{
			URL:      s.srv.URL,
			Username: "bob@candid",
		}},
	})
	c.Assert(err, qt.Equals, nil)
	ms, err := s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.Equals, nil)
	_, err = s.dischargeCreator.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Assert(err, qt.Equals, nil)
}

func (s *agentSuite) TestGetAgentDischargeNoCookie(c *qt.C) {
	client := &httprequest.Client{
		BaseURL: s.srv.URL,
	}
	err := client.Get(context.Background(), "/login/legacy-agent", nil)
	c.Assert(err, qt.ErrorMatches, `Get http://.*/login/legacy-agent: no agent-login cookie found`)
}

func (s *agentSuite) TestLegacyAgentDischarge(c *qt.C) {
	key := s.srv.CreateAgent(c, "bob@candid")
	client := s.srv.Client(nil)
	client.Key = key
	// Set up the transport so that it mutates /discharge responses
	// to delete the interaction methods so the client exercises
	// the legacy protocol instead of the current one.
	client.Transport = fakeLegacyServerTransport{client.Transport}
	err := agent.SetUpAuth(client, &agent.AuthInfo{
		Key: client.Key,
		Agents: []agent.Agent{{
			URL:      s.srv.URL,
			Username: "bob@candid",
		}},
	})
	c.Assert(err, qt.Equals, nil)
	ms, err := s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.Equals, nil)
	_, err = s.dischargeCreator.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Assert(err, qt.Equals, nil)
}

func (s *agentSuite) TestLegacyCookieAgentDischarge(c *qt.C) {
	// legacy agent protocol with cookie:
	//	    Agent                            Login Service
	//	      |                                    |
	//	      | GET visitURL with agent cookie     |
	//	      |----------------------------------->|
	//	      |                                    |
	//	      |    Macaroon with local third-party |
	//	      |                             caveat |
	//	      |<-----------------------------------|
	//	      |                                    |
	//	      | GET visitURL with agent cookie &   |
	//	      | discharged macaroon                |
	//	      |----------------------------------->|
	//	      |                                    |
	//	      |               Agent login response |
	//	      |<-----------------------------------|
	//	      |                                    |
	// Note that we don't need the agent interactor in this
	// scenario.

	key := s.srv.CreateAgent(c, "bob@candid")
	var visit func(u *url.URL) error
	client := s.srv.Client(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: func(u *url.URL) error {
			return visit(u)
		},
	})
	client.Key = key
	// Set up the transport so that it mutates /discharge responses
	// to delete the interaction methods so the client exercises
	// the legacy protocol instead of the current one.
	client.Transport = fakeLegacyServerTransport{client.Transport}
	visitCalled := false
	visit = func(u *url.URL) error {
		req, err := http.NewRequest("GET", u.String(), nil)
		c.Assert(err, qt.Equals, nil)
		resp, err := client.Do(req)
		c.Assert(err, qt.Equals, nil)
		resp.Body.Close()
		visitCalled = true
		return nil
	}
	// Set up a cookie so that the /discharge endpoint will see
	// it and respond with a self-dischargable interaction-required
	// error.
	s.setAgentCookie(client.Jar, "bob@candid", &key.Public)
	ms, err := s.dischargeCreator.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, qt.Equals, nil)
	_, err = s.dischargeCreator.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Assert(err, qt.Equals, nil)
	c.Assert(visitCalled, qt.Equals, true)
}

func (s *agentSuite) setAgentCookie(jar http.CookieJar, username string, pk *bakery.PublicKey) {
	u, err := url.Parse(s.srv.URL)
	if err != nil {
		panic(err)
	}
	al := agentLogin{
		Username:  string(username),
		PublicKey: pk,
	}
	buf, err := json.Marshal(al)
	if err != nil {
		panic(err)
	}
	jar.SetCookies(u, []*http.Cookie{{
		Name:  "agent-login",
		Value: base64.URLEncoding.EncodeToString(buf),
	}})
}

type agentLoginRequest struct {
	httprequest.Route `httprequest:"POST"`
	params.AgentLogin `httprequest:",body"`
}

type legacyAgentVisitor struct {
	username params.Username
	pk       *bakery.PublicKey
	client   *httpbakery.Client
}

// agentLogin defines the structure of an agent login cookie.
type agentLogin struct {
	Username  string            `json:"username"`
	PublicKey *bakery.PublicKey `json:"public_key"`
}

func (v *legacyAgentVisitor) OpenWebBrowserCookie(u *url.URL) error {
	al := agentLogin{
		Username:  string(v.username),
		PublicKey: v.pk,
	}
	buf, err := json.Marshal(al)
	if err != nil {
		return errgo.Mask(err)
	}
	cookie := &http.Cookie{
		Name:  "agent-login",
		Value: base64.URLEncoding.EncodeToString(buf),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return errgo.Mask(err)
	}
	req.AddCookie(cookie)
	cl := &httprequest.Client{
		Doer: v.client,
	}
	if err := cl.Do(context.Background(), req, nil); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// fakeLegacyServerTransport implements an HTTP transport
// that rewrites discharge error responses to remove the new
// InteractionMethods field so that the bakery client will
// recognise it as a legacy response and proceed accordingly.
type fakeLegacyServerTransport struct {
	t http.RoundTripper
}

var unmarshalBakeryError = httprequest.ErrorUnmarshaler(&httpbakery.Error{})

func (t fakeLegacyServerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.t == nil {
		t.t = http.DefaultTransport
	}

	resp, err := t.t.RoundTrip(req)
	if !strings.HasSuffix(req.URL.Path, "/discharge") || err != nil || resp.StatusCode == http.StatusOK {
		return resp, err
	}

	err = unmarshalBakeryError(resp)
	berr, ok := err.(*httpbakery.Error)
	if !ok {
		panic("non-bakery error returned from discharge endpoint")
	}
	if berr.Info != nil {
		berr.Info.InteractionMethods = nil
	}
	resp.Body.Close()
	bodyData, err := json.Marshal(berr)
	if err != nil {
		panic("cannot re-marshal bakery error")
	}
	resp.Body = ioutil.NopCloser(bytes.NewReader(bodyData))
	return resp, nil
}
