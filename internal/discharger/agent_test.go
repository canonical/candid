// Copyright 2015 Canonical Ltd.

package discharger_test

import (
	"net/url"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
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
	err := agent.SetUpAuth(client, s.URL, username)
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
	client.WebPageVisitor = httpbakery.NewMultiVisitor(&agentVisitor{
		params.Username(username),
		&key.Public,
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

type agentVisitor struct {
	username params.Username
	pk       *bakery.PublicKey
}

func (v *agentVisitor) VisitWebPage(ctx context.Context, client *httpbakery.Client, m map[string]*url.URL) error {
	agentURL, ok := m["agent"]
	if !ok {
		return httpbakery.ErrMethodNotSupported
	}
	cl := &httprequest.Client{
		Doer: client,
	}
	req := &agentLoginRequest{
		AgentLogin: params.AgentLogin{
			Username:  v.username,
			PublicKey: v.pk,
		},
	}
	if err := cl.CallURL(ctx, agentURL.String(), req, nil); err != nil {
		return errgo.Mask(err)
	}
	return nil
}
