// Copyright 2015 Canonical Ltd.

package v1_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"

	"github.com/CanonicalLtd/blues-identity/internal/v1"
	"github.com/CanonicalLtd/blues-identity/params"
)

type agentSuite struct{}

var _ = gc.Suite(&agentSuite{})

var agentLoginFromCookieTests = []struct {
	about       string
	value       string
	expectError string
}{{
	about: "no username",
	value: encode(params.AgentLogin{
		Username:  "",
		PublicKey: &testKey().Public,
	}),
	expectError: `cannot unmarshal agent login: illegal username ""`,
}, {
	about: "no public_key",
	value: encode(params.AgentLogin{
		Username:  "user",
		PublicKey: nil,
	}),
	expectError: `agent login has no public key`,
}, {
	about:       "bad base64",
	value:       "A",
	expectError: `cannot decode cookie value: .*`,
}}

func (*agentSuite) TestGetAgentLoginFromCookie(c *gc.C) {
	for i, test := range agentLoginFromCookieTests {
		c.Logf("%d. %s", i, test.about)
		r, err := http.NewRequest("GET", "", nil)
		c.Assert(err, gc.IsNil)
		r.AddCookie(&http.Cookie{
			Name:  "agent-login",
			Value: test.value,
		})
		_, err = v1.GetAgentLoginFromCookie(r)
		c.Assert(err, gc.ErrorMatches, test.expectError)
	}
}

func encode(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func testKey() *bakery.KeyPair {
	k, err := bakery.GenerateKey()
	if err != nil {
		panic(err)
	}
	return k
}
