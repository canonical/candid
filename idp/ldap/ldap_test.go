// Copyright 2017 Canonical Ltd.

package ldap_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/ldap"
	"github.com/CanonicalLtd/blues-identity/store"
)

type ldapSuite struct {
	idptest.Suite

	ldapDialer *mockLDAPDialer
}

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

var sampleLdapDb = ldapDB{{
	// admin user (used for search binds)
	"dn":           {"cn=test,dc=example,dc=com"},
	"userPassword": {"pass"},
}, {
	"dn":           {"uid=user1,ou=users,dc=example,dc=com"},
	"objectClass":  {"account"},
	"uid":          {"user1"},
	"userPassword": {"pass1"},
}, {
	"dn":           {"uid=user2,ou=users,dc=example,dc=com"},
	"objectClass":  {"account"},
	"uid":          {"user2"},
	"userPassword": {"pass2"},
}}

func (s *ldapSuite) setupIdp(c *gc.C, params ldap.Params, db ldapDB) idp.IdentityProvider {
	i, err := ldap.NewIdentityProvider(params)
	c.Assert(err, gc.IsNil)
	s.ldapDialer = newMockLDAPDialer(db)
	ldap.SetLDAP(i, s.ldapDialer.Dial)
	i.Init(context.TODO(), s.InitParams(c, "https://example.com/test"))
	return i
}

func (s *ldapSuite) makeLoginRequest(c *gc.C, i idp.IdentityProvider, username, password string) *httptest.ResponseRecorder {
	req, err := http.NewRequest("POST", "/login",
		strings.NewReader(
			url.Values{
				"username": {username},
				"password": {password},
			}.Encode(),
		),
	)
	c.Assert(err, gc.IsNil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rr := httptest.NewRecorder()
	i.Handle(context.TODO(), rr, req)
	return rr
}

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

func (s *ldapSuite) TestHandle(c *gc.C) {
	params := ldap.Params{
		Name:     "test",
		Domain:   "ldap",
		URL:      "ldap://localhost",
		DN:       "cn=test,dc=example,dc=com",
		Password: "pass",
	}
	i := s.setupIdp(c, params, sampleLdapDb)
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.AssertLoginSuccess(c, "user1@ldap")
	s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity(
			"test", "uid=user1,ou=users,dc=example,dc=com"),
		Username: "user1@ldap",
	})
}

func (s *ldapSuite) TestHandleWithGroups(c *gc.C) {
	params := ldap.Params{
		Name:     "test",
		Domain:   "ldap",
		URL:      "ldap://localhost",
		DN:       "cn=test,dc=example,dc=com",
		Password: "pass",
	}
	groups := []ldapDoc{{
		"dn":          {"cn=group1,ou=users,dc=example,dc=com"},
		"objectClass": {"groupOfNames"},
		"cn":          {"group1"},
		"member": {
			"uid=user1,ou=users,dc=example,dc=com",
			"uid=user2,ou=users,dc=example,dc=com",
		},
	}, {
		"dn":          {"cn=group2,ou=users,dc=example,dc=com"},
		"objectClass": {"groupOfNames"},
		"cn":          {"group2"},
		"member":      {"uid=user1,ou=users,dc=example,dc=com"},
	}}
	sampleDb := append(sampleLdapDb, groups...)
	i := s.setupIdp(c, params, sampleDb)
	s.makeLoginRequest(c, i, "user1", "pass1")
	s.AssertLoginSuccess(c, "user1@ldap")
	s.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity(
			"test", "uid=user1,ou=users,dc=example,dc=com"),
		Username: "user1@ldap",
		Groups:   []string{"group1", "group2"},
	})
}

func (s *ldapSuite) TestHandleFailedLogin(c *gc.C) {
	params := ldap.Params{
		Name:     "test",
		Domain:   "ldap",
		URL:      "ldap://localhost",
		DN:       "cn=test,dc=example,dc=com",
		Password: "pass",
	}
	i := s.setupIdp(c, params, sampleLdapDb)
	s.makeLoginRequest(c, i, "user1", "wrong")
	s.AssertLoginFailureMatches(c, `Login failure`)
}
