// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/candid/internal/candidtest"
)

type agentSuite struct {
	candidtest.DischargeSuite
}

var _ = gc.Suite(&agentSuite{})

func (s *agentSuite) TestHTTPBakeryAgentDischarge(c *gc.C) {
	key := s.CreateAgent(c, "bob@idm")
	client := s.Client(nil)
	client.Key = key
	err := agent.SetUpAuth(client, &agent.AuthInfo{
		Key: client.Key,
		Agents: []agent.Agent{{
			URL:      s.URL,
			Username: "bob@idm",
		}},
	})
	c.Assert(err, gc.Equals, nil)
	ms, err := s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	_, err = s.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Assert(err, gc.Equals, nil)
}

func (s *agentSuite) TestGetAgentDischargeNoCookie(c *gc.C) {
	client := &httprequest.Client{
		BaseURL: s.URL,
	}
	err := client.Get(context.Background(), "/login/legacy-agent", nil)
	c.Assert(err, gc.ErrorMatches, `Get http://.*/login/legacy-agent: no agent-login cookie found`)
}

func (s *agentSuite) TestLegacyAgentDischarge(c *gc.C) {
	key := s.CreateAgent(c, "bob@idm")
	client := s.Client(nil)
	client.Key = key
	// Set up the transport so that it mutates /discharge responses
	// to delete the interaction methods so the client exercises
	// the legacy protocol instead of the current one.
	client.Transport = fakeLegacyServerTransport{client.Transport}
	err := agent.SetUpAuth(client, &agent.AuthInfo{
		Key: client.Key,
		Agents: []agent.Agent{{
			URL:      s.URL,
			Username: "bob@idm",
		}},
	})
	c.Assert(err, gc.Equals, nil)
	ms, err := s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	_, err = s.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Assert(err, gc.Equals, nil)
}

func (s *agentSuite) TestLegacyCookieAgentDischarge(c *gc.C) {
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

	key := s.CreateAgent(c, "bob@idm")
	var visit func(u *url.URL) error
	client := s.Client(httpbakery.WebBrowserInteractor{
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
		c.Assert(err, gc.Equals, nil)
		resp, err := client.Do(req)
		c.Assert(err, gc.Equals, nil)
		resp.Body.Close()
		visitCalled = true
		return nil
	}
	// Set up a cookie so that the /discharge endpoint will see
	// it and respond with a self-dischargable interaction-required
	// error.
	s.setAgentCookie(client.Jar, "bob@idm", &key.Public)
	ms, err := s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	_, err = s.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Assert(err, gc.Equals, nil)
	c.Assert(visitCalled, gc.Equals, true)
}

func (s *agentSuite) setAgentCookie(jar http.CookieJar, username string, pk *bakery.PublicKey) {
	u, err := url.Parse(s.URL)
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
