// Copyright 2015 Canonical Ltd.

package v1_test

import (
	"net/url"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	httpbakeryagent "gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent"

	"github.com/CanonicalLtd/blues-identity/idp/idptest"
)

type agentSuite struct {
	idptest.DischargeSuite
	agentKey *bakery.KeyPair
}

var _ = gc.Suite(&agentSuite{})

func (s *agentSuite) SetUpTest(c *gc.C) {
	s.DischargeSuite.SetUpTest(c)
	var err error
	s.agentKey, err = bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
}

func (s *agentSuite) TestHTTPBakeryAgentDischarge(c *gc.C) {
	err := s.IDMClient.SetUser(context.TODO(), &params.SetUserRequest{
		Username: params.Username("test@admin@idm"),
		User: params.User{
			Username: params.Username("test@admin@idm"),
			Owner:    "admin@idm",
			PublicKeys: []*bakery.PublicKey{
				&s.agentKey.Public,
			},
		},
	})
	c.Assert(err, gc.IsNil)
	s.BakeryClient.Key = s.agentKey
	httpbakeryagent.SetUpAuth(s.BakeryClient, idptest.DischargeLocation, "test@admin@idm")
	s.AssertDischarge(c, nil)
	c.Assert(err, gc.IsNil)
}

func (s *agentSuite) TestGetAgentDischargeNoCookie(c *gc.C) {
	err := s.HTTPRequestClient.Get(context.TODO(), s.Server.URL+"/v1/agent-login", nil)
	c.Assert(err, gc.ErrorMatches, `Get http://.*/v1/agent-login: no agent-login cookie found`)
}

func (s *agentSuite) TestLegacyAgentDischarge(c *gc.C) {
	err := s.IDMClient.SetUser(context.TODO(), &params.SetUserRequest{
		Username: params.Username("test@admin@idm"),
		User: params.User{
			Username: params.Username("test@admin@idm"),
			Owner:    "admin@idm",
			PublicKeys: []*bakery.PublicKey{
				&s.agentKey.Public,
			},
		},
	})
	c.Assert(err, gc.IsNil)
	s.BakeryClient.Key = s.agentKey
	s.AssertDischarge(c,
		httpbakery.NewMultiVisitor(&agentVisitor{
			"test@admin@idm",
			&s.agentKey.Public,
		}),
	)
	c.Assert(err, gc.IsNil)
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
