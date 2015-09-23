// Copyright 2015 Canonical Ltd.

package idp_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"

	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/internal/idp"
	"github.com/CanonicalLtd/blues-identity/params"
	"github.com/juju/testing/httptesting"
)

type agentSuite struct {
	idpSuite
	idp *idp.AgentIdentityProvider
}

var _ = gc.Suite(&agentSuite{})

func (s *agentSuite) SetUpTest(c *gc.C) {
	s.idpSuite.SetUpTest(c)
	var err error
	s.idp, err = idp.NewAgentIdentityProvider("https://example.com/identity")
	c.Assert(err, gc.IsNil)
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
	tc := &testContext{}
	u, err := s.idp.URL(tc, "1")
	c.Assert(err, gc.IsNil)
	c.Assert(u, gc.Equals, "https://idp.test/agent?waitid=1")
}

func (s *agentSuite) TestHandleBadRequest(c *gc.C) {
	tc := testContext{
		store: s.store,
	}
	tc.params.Request = &http.Request{
		URL: &url.URL{
			Path: "/",
		},
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
		},
		Body: ioutil.NopCloser(bytes.NewReader(nil)),
	}
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	s.idp.Handle(&tc)
	c.Assert(tc.err, gc.ErrorMatches, "cannot unmarshal request: cannot unmarshal into field: unexpected content type text/plain; want application/json; content: ")
	c.Assert(rr.Body.Len(), gc.Equals, 0)
}

func (s *agentSuite) TestHandleNoMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := testContext{
		store: s.store,
	}
	tc.params.Request = &http.Request{
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
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	s.idp.Handle(&tc)
	s.assertDischargeRequired(c, rr)
}

func (s *agentSuite) TestHandleWithUsableMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := testContext{
		store: s.store,
	}
	tc.params.Request = &http.Request{
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
	tc.params.Request.AddCookie(cookie)
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	tc.success = true
	s.idp.Handle(&tc)
	c.Assert(tc.macaroon, gc.Not(gc.IsNil))
	httptesting.AssertJSONResponse(c, rr, http.StatusOK, params.AgentLoginResponse{
		AgentLogin: true,
	})
}

func (s *agentSuite) TestHandleWithUnsableMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := testContext{
		store: s.store,
	}
	tc.params.Request = &http.Request{
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
	tc.params.Request.AddCookie(cookie)
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	tc.success = true
	s.idp.Handle(&tc)
	c.Assert(tc.macaroon, gc.IsNil)
	s.assertDischargeRequired(c, rr)
}

func (s *agentSuite) TestHandleShortcutNoMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := testAgentLoginer{
		testContext: testContext{
			store: s.store,
		},
		agentLogin: params.AgentLogin{
			Username:  "test",
			PublicKey: &key.Public,
		},
	}
	tc.params.Request = &http.Request{
		URL: &url.URL{
			Path: "/",
		},
		Header: http.Header{},
	}
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	s.idp.Handle(&tc)
	s.assertDischargeRequired(c, rr)
}

func (s *agentSuite) TestHandleWithShortcutUsableMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := testAgentLoginer{
		testContext: testContext{
			store: s.store,
		},
		agentLogin: params.AgentLogin{
			Username:  "test",
			PublicKey: &key.Public,
		},
	}
	tc.params.Request, err = http.NewRequest("", "", nil)
	c.Assert(err, gc.IsNil)
	m, err := s.store.Service.NewMacaroon("", nil, []checkers.Caveat{})
	c.Assert(err, gc.IsNil)
	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
	c.Assert(err, gc.IsNil)
	tc.params.Request.AddCookie(cookie)
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	tc.success = true
	s.idp.Handle(&tc)
	c.Assert(tc.macaroon, gc.Not(gc.IsNil))
	httptesting.AssertJSONResponse(c, rr, http.StatusOK, params.AgentLoginResponse{
		AgentLogin: true,
	})
}

func (s *agentSuite) TestHandleShortcutWithUnsableMacaroon(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	tc := testAgentLoginer{
		testContext: testContext{
			store: s.store,
		},
		agentLogin: params.AgentLogin{
			Username:  "test",
			PublicKey: &key.Public,
		},
	}
	tc.params.Request, err = http.NewRequest("", "/", nil)
	c.Assert(err, gc.IsNil)
	m, err := s.store.Service.NewMacaroon("", nil, []checkers.Caveat{checkers.DenyCaveat("discharge")})
	c.Assert(err, gc.IsNil)
	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
	c.Assert(err, gc.IsNil)
	tc.params.Request.AddCookie(cookie)
	rr := httptest.NewRecorder()
	tc.params.Response = rr
	tc.success = true
	s.idp.Handle(&tc)
	c.Assert(tc.macaroon, gc.IsNil)
	s.assertDischargeRequired(c, rr)
}

func (s *agentSuite) assertDischargeRequired(c *gc.C, rr *httptest.ResponseRecorder) {
	c.Assert(rr.Code, gc.Equals, http.StatusProxyAuthRequired)
	var herr httpbakery.Error
	err := json.Unmarshal(rr.Body.Bytes(), &herr)
	c.Assert(err, gc.IsNil)
	c.Assert(herr.Info.Macaroon, gc.Not(gc.IsNil))
}

type testAgentLoginer struct {
	testContext
	agentLogin params.AgentLogin
}

func (t *testAgentLoginer) AgentLogin() params.AgentLogin {
	return t.agentLogin
}
