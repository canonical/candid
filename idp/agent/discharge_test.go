// Copyright 2015 Canonical Ltd.

package agent_test

import (
	"net/url"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	httpbakeryagent "gopkg.in/macaroon-bakery.v1/httpbakery/agent"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/agent"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
)

type dischargeSuite struct {
	idptest.DischargeSuite
	agentKey *bakery.KeyPair
}

var _ = gc.Suite(&dischargeSuite{})

func (s *dischargeSuite) SetUpTest(c *gc.C) {
	s.IDPs = []idp.IdentityProvider{
		agent.IdentityProvider,
	}
	s.DischargeSuite.SetUpTest(c)
	var err error
	s.agentKey, err = bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
}

func (s *dischargeSuite) TestHTTPBakeryAgentDischarge(c *gc.C) {
	err := s.IDMClient.SetUser(&params.SetUserRequest{
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
	u, err := url.Parse(idptest.DischargeLocation)
	c.Assert(err, gc.IsNil)
	s.BakeryClient.Key = s.agentKey
	httpbakeryagent.SetUpAuth(s.BakeryClient, u, "test@admin@idm")
	s.AssertDischarge(c, nil, checkers.New(
		checkers.TimeBefore,
	))
	c.Assert(err, gc.IsNil)
}

func (s *dischargeSuite) TestLegacyAgentDischarge(c *gc.C) {
	err := s.IDMClient.SetUser(&params.SetUserRequest{
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
		agentVisit(c,
			s.BakeryClient,
			"test@admin@idm",
			&s.agentKey.Public,
		),
		checkers.New(
			checkers.TimeBefore,
		),
	)
	c.Assert(err, gc.IsNil)
}

type agentLoginRequest struct {
	httprequest.Route `httprequest:"POST"`
	params.AgentLogin `httprequest:",body"`
}

func agentVisit(c *gc.C, client *httpbakery.Client, username string, pk *bakery.PublicKey) func(u *url.URL) error {
	return func(u *url.URL) error {
		cl := &httprequest.Client{
			Doer: client,
		}
		var loginMethods params.LoginMethods
		if err := idputil.GetLoginMethods(cl, u, &loginMethods); err != nil {
			return errgo.Mask(err)
		}
		req := &agentLoginRequest{
			AgentLogin: params.AgentLogin{
				Username:  params.Username(username),
				PublicKey: pk,
			},
		}
		if err := cl.CallURL(loginMethods.Agent, req, nil); err != nil {
			return errgo.Mask(err)
		}
		return nil
	}
}
