// Copyright 2017 Canonical Ltd.

package ldap_test

import (
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/ldap"
)

type ldapSuite struct{}

var _ = gc.Suite(&ldapSuite{})

var newTests = []struct {
	about       string
	params      ldap.Params
	expectError string
}{{
	about: "good params",
	params: ldap.Params{
		Name: "ldap",
		URL:  "ldap://localhost",
	},
}, {
	about: "unparsable url",
	params: ldap.Params{
		Name: "ldap",
		URL:  "://",
	},
	expectError: `cannot parse URL: parse ://: missing protocol scheme`,
}, {
	about: "unsupported scheme",
	params: ldap.Params{
		Name: "ldaps",
		URL:  "ldaps://",
	},
	expectError: `unsupported scheme "ldaps"`,
}}

func (s *ldapSuite) TestNewIdentityProvider(c *gc.C) {
	for i, test := range newTests {
		c.Logf("test %d. %s", i, test.about)
		idp, err := ldap.NewIdentityProvider(test.params)
		if test.expectError == "" {
			c.Assert(err, gc.Equals, nil)
			c.Assert(idp, gc.Not(gc.IsNil))
			continue
		}
		c.Assert(err, gc.ErrorMatches, test.expectError)
		c.Assert(idp, gc.IsNil)
	}
}

func (s *ldapSuite) TestName(c *gc.C) {
	idp, err := ldap.NewIdentityProvider(ldap.Params{
		Name: "test",
		URL:  "ldap://localhost",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(idp.Name(), gc.Equals, "test")
}

func (s *ldapSuite) TestDescription(c *gc.C) {
	idp, err := ldap.NewIdentityProvider(ldap.Params{
		Name:        "test",
		Description: "test description",
		URL:         "ldap://localhost",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(idp.Description(), gc.Equals, "test description")
}

func (s *ldapSuite) TestDomain(c *gc.C) {
	idp, err := ldap.NewIdentityProvider(ldap.Params{
		Name:   "test",
		Domain: "test domain",
		URL:    "ldap://localhost",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(idp.Domain(), gc.Equals, "test domain")
}

func (s *ldapSuite) TestInteractive(c *gc.C) {
	idp, err := ldap.NewIdentityProvider(ldap.Params{
		Name: "test",
		URL:  "ldap://localhost",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(idp.Interactive(), gc.Equals, true)
}

func (s *ldapSuite) TestURL(c *gc.C) {
	i, err := ldap.NewIdentityProvider(ldap.Params{
		Name: "test",
		URL:  "ldap://localhost",
	})
	c.Assert(err, gc.Equals, nil)
	i.Init(context.Background(), idp.InitParams{
		URLPrefix: "https://example.com/test",
	})
	c.Assert(i.URL("1"), gc.Equals, "https://example.com/test/login?id=1")
}
