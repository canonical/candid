// Copyright 2015 Canonical Ltd.

package agent_test

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/juju/idmclient/params"
	"github.com/juju/testing"
	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon.v1"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/agent"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

type agentSuite struct {
	testing.IsolatedMgoSuite
	idp   idp.IdentityProvider
	pool  *store.Pool
	store *store.Store
}

var _ = gc.Suite(&agentSuite{})

func (s *agentSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	s.idp = agent.IdentityProvider
	var err error
	s.pool, err = store.NewPool(s.Session.DB("testing"), store.StoreParams{
		PrivateAddr: "localhost",
	})
	c.Assert(err, gc.IsNil)
	s.store = s.pool.GetNoLimit()
}

func (s *agentSuite) TearDownTest(c *gc.C) {
	s.store.Close()
	s.pool.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

func (s *agentSuite) TestConfig(c *gc.C) {
	configYaml := `
identity-providers:
 - type: agent
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(configYaml), &conf)
	c.Assert(err, gc.IsNil)
	c.Assert(conf.IdentityProviders, gc.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), gc.Equals, "agent")
}

func (s *agentSuite) TestName(c *gc.C) {
	c.Assert(s.idp.Name(), gc.Equals, "agent")
}

func (s *agentSuite) TestDescription(c *gc.C) {
	c.Assert(s.idp.Description(), gc.Equals, "Agent")
}

func (s *agentSuite) TestInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, false)
}

func (s *agentSuite) TestURL(c *gc.C) {
	tc := &agentContext{
		TestContext: idptest.TestContext{
			URLPrefix: "https://idp.test/agent",
		},
	}
	u, err := s.idp.URL(tc, "1")
	c.Assert(err, gc.IsNil)
	c.Assert(u, gc.Equals, "https://idp.test/agent/agent?waitid=1")
}

func (s *agentSuite) TestHandleBadRequest(c *gc.C) {
	tc := &agentContext{
		TestContext: idptest.TestContext{
			URLPrefix: "https://idp.test/agent",
		},
	}
	tc.Request = &http.Request{
		URL: &url.URL{
			Path: "/",
		},
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
		},
		Body: ioutil.NopCloser(bytes.NewReader(nil)),
	}
	s.idp.Handle(tc)
	idptest.AssertLoginFailure(c, &tc.TestContext, "cannot unmarshal request: cannot unmarshal into field: unexpected content type text/plain; want application/json; content: ")
	c.Assert(tc.Response().Body.Len(), gc.Equals, 0)
}

func (s *agentSuite) TestHandleNoMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := &agentContext{
		TestContext: idptest.TestContext{
			URLPrefix: "https://idp.test/agent",
			Bakery_:   s.store.Service,
		},
	}
	tc.Request = &http.Request{
		URL: &url.URL{
			Path: "/",
		},
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: body(params.AgentLogin{
			Username:  "test",
			PublicKey: &key.Public,
		}),
	}
	s.idp.Handle(tc)
	s.assertDischargeRequired(c, tc.Response())
}

func (s *agentSuite) TestHandleWithUsableMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := &agentContext{
		TestContext: idptest.TestContext{
			URLPrefix: "https://idp.test/agent",
			Bakery_:   s.store.Service,
		},
		store: s.store,
	}
	tc.Request = &http.Request{
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: body(params.AgentLogin{
			Username:  "test",
			PublicKey: &key.Public,
		}),
	}
	m, err := s.store.Service.NewMacaroon("", nil, []checkers.Caveat{})
	c.Assert(err, gc.IsNil)
	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
	c.Assert(err, gc.IsNil)
	tc.Request.AddCookie(cookie)
	s.idp.Handle(tc)
	idptest.AssertLoginSuccess(c, &tc.TestContext, checkers.New(
		checkers.TimeBefore,
	), nil)
	httptesting.AssertJSONResponse(c, tc.Response(), http.StatusOK, params.AgentLoginResponse{
		AgentLogin: true,
	})
}

func (s *agentSuite) TestHandleWithUnsableMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := &agentContext{
		TestContext: idptest.TestContext{
			URLPrefix: "https://idp.test/agent",
			Bakery_:   s.store.Service,
		},
		store: s.store,
	}
	tc.Request = &http.Request{
		URL: &url.URL{
			Path: "/",
		},
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: body(params.AgentLogin{
			Username:  "test",
			PublicKey: &key.Public,
		}),
	}
	m, err := s.store.Service.NewMacaroon("", nil, []checkers.Caveat{checkers.DenyCaveat("discharge")})
	c.Assert(err, gc.IsNil)
	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
	c.Assert(err, gc.IsNil)
	tc.Request.AddCookie(cookie)
	s.idp.Handle(tc)
	idptest.AssertLoginInProgress(c, &tc.TestContext)
	s.assertDischargeRequired(c, tc.Response())
}

func (s *agentSuite) TestHandleShortcutNoMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := &agentContext{
		TestContext: idptest.TestContext{
			URLPrefix: "https://idp.test/agent",
			Bakery_:   s.store.Service,
		},
		agentLogin: params.AgentLogin{
			Username:  "test",
			PublicKey: &key.Public,
		},
	}
	tc.Request = &http.Request{
		URL: &url.URL{
			Path: "/",
		},
		Header: http.Header{},
	}
	s.idp.Handle(tc)
	idptest.AssertLoginInProgress(c, &tc.TestContext)
	s.assertDischargeRequired(c, tc.Response())
}

func (s *agentSuite) TestHandleWithShortcutUsableMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := &agentContext{
		TestContext: idptest.TestContext{
			URLPrefix: "https://idp.test/agent",
			Bakery_:   s.store.Service,
		},
		agentLogin: params.AgentLogin{
			Username:  "test",
			PublicKey: &key.Public,
		},
	}
	tc.Request, err = http.NewRequest("", "", nil)
	c.Assert(err, gc.IsNil)
	m, err := s.store.Service.NewMacaroon("", nil, []checkers.Caveat{})
	c.Assert(err, gc.IsNil)
	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
	c.Assert(err, gc.IsNil)
	tc.Request.AddCookie(cookie)
	s.idp.Handle(tc)
	idptest.AssertLoginSuccess(c, &tc.TestContext, checkers.New(
		checkers.TimeBefore,
	), nil)
	httptesting.AssertJSONResponse(c, tc.Response(), http.StatusOK, params.AgentLoginResponse{
		AgentLogin: true,
	})
}

func (s *agentSuite) TestHandleShortcutWithUnsableMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := &agentContext{
		TestContext: idptest.TestContext{
			URLPrefix: "https://idp.test/agent",
			Bakery_:   s.store.Service,
		},
		agentLogin: params.AgentLogin{
			Username:  "test",
			PublicKey: &key.Public,
		},
	}
	tc.Request, err = http.NewRequest("", "/login", nil)
	c.Assert(err, gc.IsNil)
	m, err := s.store.Service.NewMacaroon("", nil, []checkers.Caveat{checkers.DenyCaveat("discharge")})
	c.Assert(err, gc.IsNil)
	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
	c.Assert(err, gc.IsNil)
	tc.Request.AddCookie(cookie)
	s.idp.Handle(tc)
	idptest.AssertLoginInProgress(c, &tc.TestContext)
	s.assertDischargeRequired(c, tc.Response())
}

func (s *agentSuite) assertDischargeRequired(c *gc.C, rr *httptest.ResponseRecorder) {
	c.Assert(rr.Code, gc.Equals, http.StatusProxyAuthRequired)
	var herr httpbakery.Error
	err := json.Unmarshal(rr.Body.Bytes(), &herr)
	c.Assert(err, gc.IsNil)
	c.Assert(herr.Info.Macaroon, gc.Not(gc.IsNil))
	_, ok := checkers.ExpiryTime(herr.Info.Macaroon.Caveats())
	c.Assert(ok, gc.Equals, true)
}

type agentContext struct {
	idptest.TestContext
	agentLogin params.AgentLogin
	store      *store.Store
}

func (c *agentContext) AgentLogin() params.AgentLogin {
	return c.agentLogin
}

func (c *agentContext) Store() *store.Store {
	return c.store
}

func body(v interface{}) io.ReadCloser {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return ioutil.NopCloser(bytes.NewReader(data))
}
