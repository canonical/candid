// Copyright 2015 Canonical Ltd.

package identity_test

import (
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	intidp "github.com/CanonicalLtd/blues-identity/internal/idp"
)

type idpSuite struct{}

var _ = gc.Suite(&idpSuite{})

var newIDPTests = []struct {
	about       string
	idp         idp.IdentityProvider
	expect      identity.IdentityProvider
	expectError string
}{{
	about:  "Ubuntu SSO",
	idp:    idp.UbuntuSSOIdentityProvider,
	expect: intidp.NewUSSOIdentityProvider(),
}, {
	about:  "Ubuntu SSO OAuth",
	idp:    idp.UbuntuSSOOAuthIdentityProvider,
	expect: &intidp.USSOOAuthIdentityProvider{},
}, {
	about:  "Agent",
	idp:    idp.AgentIdentityProvider,
	expect: mustIDP(intidp.NewAgentIdentityProvider("https://idm.test/")),
}, {
	about: "not found",
	idp: idp.IdentityProvider{
		Type: "unknown type",
	},
	expectError: `unknown provider type "unknown type"`,
}}

func (s *idpSuite) TestNewIDP(c *gc.C) {
	sp := identity.ServerParams{
		Location: "https://idm.test/",
	}
	for i, test := range newIDPTests {
		c.Logf("%d. %s", i, test.about)
		obtained, err := identity.NewIDP(sp, test.idp)
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			continue
		}
		c.Assert(err, gc.IsNil)
		c.Assert(obtained, jc.DeepEquals, test.expect)
	}
}

func mustIDP(idp identity.IdentityProvider, err error) identity.IdentityProvider {
	if err != nil {
		panic(err)
	}
	return idp
}

var newkeystoneIDPTests = []struct {
	about  string
	idp    idp.IdentityProvider
	expect interface{}
}{{
	about:  "Keystone",
	idp:    idp.KeystoneIdentityProvider(&idp.KeystoneParams{}),
	expect: intidp.NewKeystoneIdentityProvider(&idp.KeystoneParams{}),
}, {
	about:  "Keystone Userpass",
	idp:    idp.KeystoneUserpassIdentityProvider(&idp.KeystoneParams{}),
	expect: intidp.NewKeystoneUserpassIdentityProvider(&idp.KeystoneParams{}),
}, {
	about:  "Keystone Token",
	idp:    idp.KeystoneTokenIdentityProvider(&idp.KeystoneParams{}),
	expect: intidp.NewKeystoneTokenIdentityProvider(&idp.KeystoneParams{}),
}}

func (s *idpSuite) TestNewKeystoneIDP(c *gc.C) {
	sp := identity.ServerParams{
		Location: "https://idm.test/",
	}
	for i, test := range newkeystoneIDPTests {
		c.Logf("%d. %s", i, test.about)
		obtained, err := identity.NewIDP(sp, test.idp)
		c.Assert(err, gc.IsNil)
		c.Assert(obtained, gc.FitsTypeOf, test.expect)
	}
}
