// Copyright 2015 Canonical Ltd.

package discharger_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent"

	"github.com/CanonicalLtd/blues-identity/internal/auth"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
)

type agentSuite struct {
	idmtest.DischargeSuite
}

var _ = gc.Suite(&agentSuite{})

func (s *agentSuite) TestHTTPBakeryAgentDischarge(c *gc.C) {
	username, key := s.CreateAgent(c, "bob", auth.AdminUsername)
	client := s.Client(nil)
	client.Key = key
	err := agent.SetUpAuth(client, &agent.AuthInfo{
		Key: client.Key,
		Agents: []agent.Agent{{
			URL:      s.URL,
			Username: username,
		}},
	})
	c.Assert(err, gc.Equals, nil)
	ms, err := s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	_, err = s.Bakery.Checker.Auth(ms).Allow(context.Background(), bakery.LoginOp)
	c.Assert(err, gc.Equals, nil)
}

func (s *agentSuite) TestGetAgentDischargeNoCookie(c *gc.C) {
	client := &httprequest.Client{
		BaseURL: s.URL,
	}
	err := client.Get(context.Background(), "/login/agent", nil)
	c.Assert(err, gc.ErrorMatches, `Get http://.*/login/agent: no agent-login cookie found`)
}

func (s *agentSuite) TestLegacyAgentDischarge(c *gc.C) {
	username, key := s.CreateAgent(c, "bob", auth.AdminUsername)
	client := s.Client(nil)
	client.Key = key
	visitor := &legacyAgentVisitor{
		username: params.Username(username),
		pk:       &key.Public,
		client:   client,
	}
	client.AddInteractor(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: visitor.OpenWebBrowser,
	})
	ms, err := s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	_, err = s.Bakery.Checker.Auth(ms).Allow(context.Background(), bakery.LoginOp)
	c.Assert(err, gc.Equals, nil)
}

func (s *agentSuite) TestLegacyCookieAgentDischarge(c *gc.C) {
	username, key := s.CreateAgent(c, "bob", auth.AdminUsername)
	client := s.Client(nil)
	client.Key = key
	visitor := &legacyAgentVisitor{
		username: params.Username(username),
		pk:       &key.Public,
		client:   client,
	}
	client.AddInteractor(httpbakery.WebBrowserInteractor{
		OpenWebBrowser: visitor.OpenWebBrowserCookie,
	})
	ms, err := s.Discharge(c, "is-authenticated-user", client)
	c.Assert(err, gc.Equals, nil)
	_, err = s.Bakery.Checker.Auth(ms).Allow(context.Background(), bakery.LoginOp)
	c.Assert(err, gc.Equals, nil)
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

func (v *legacyAgentVisitor) OpenWebBrowser(u *url.URL) error {
	lm, err := idmclient.LoginMethods(v.client.Client, u)
	if err != nil {
		return errgo.Mask(err)
	}
	if lm.Agent == "" {
		return errgo.New("agent login not supported")
	}
	cl := &httprequest.Client{
		Doer: v.client,
	}
	req := &agentLoginRequest{
		AgentLogin: params.AgentLogin{
			Username:  params.Username(v.username),
			PublicKey: v.pk,
		},
	}
	if err := cl.CallURL(context.Background(), lm.Agent, req, nil); err != nil {
		return errgo.Mask(err)
	}
	return nil
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
