// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package ldap_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idptest"
	"github.com/CanonicalLtd/candid/idp/ldap"
	"github.com/CanonicalLtd/candid/internal/candidtest"
	"github.com/CanonicalLtd/candid/store"
)

const idpPrefix = "http://idp.example.com"

type ldapSuite struct {
	idptest *idptest.Fixture
}

func TestLDAP(t *testing.T) {
	qtsuite.Run(qt.New(t), &ldapSuite{})
}

func (s *ldapSuite) Init(c *qt.C) {
	s.idptest = idptest.NewFixture(c, candidtest.NewStore())
}

var newTests = []struct {
	about       string
	params      ldap.Params
	expectError string
}{{
	about: "good params",
	params: ldap.Params{
		Name:             "ldap",
		URL:              "ldap://localhost",
		UserQueryFilter:  "(userAttr=val)",
		UserQueryAttrs:   ldap.UserQueryAttrs{ID: "uid"},
		GroupQueryFilter: "(groupAttr=val)",
	},
}, {
	about: "unparsable url",
	params: ldap.Params{
		Name:             "ldap",
		URL:              "://",
		UserQueryFilter:  "(userAttr=val)",
		UserQueryAttrs:   ldap.UserQueryAttrs{ID: "uid"},
		GroupQueryFilter: "(groupAttr=val)",
	},
	expectError: `cannot parse URL: parse "?://"?: missing protocol scheme`,
}, {
	about: "unsupported scheme",
	params: ldap.Params{
		Name:             "ldaps",
		URL:              "ldaps://",
		UserQueryFilter:  "(userAttr=val)",
		UserQueryAttrs:   ldap.UserQueryAttrs{ID: "uid"},
		GroupQueryFilter: "(groupAttr=val)",
	},
	expectError: `unsupported scheme "ldaps"`,
}, {
	about: "missing user query filter",
	params: ldap.Params{
		Name:             "ldap",
		URL:              "://",
		UserQueryAttrs:   ldap.UserQueryAttrs{ID: "uid"},
		GroupQueryFilter: "(groupAttr=val)",
	},
	expectError: `missing 'user-query-filter' config parameter`,
}, {
	about: "missing group query filter",
	params: ldap.Params{
		Name:            "ldap",
		URL:             "://",
		UserQueryFilter: "(userAttr=val)",
		UserQueryAttrs:  ldap.UserQueryAttrs{ID: "uid"},
	},
	expectError: `missing 'group-query-filter' config parameter`,
}, {
	about: "missing group attributes ID",
	params: ldap.Params{
		Name:             "ldap",
		URL:              "://",
		UserQueryFilter:  "(userAttr=val)",
		GroupQueryFilter: "(groupAttr=val)",
	},
	expectError: `missing 'id' config parameter in 'user-query-attrs'`,
}, {
	about: "invalid group query filter template",
	params: ldap.Params{
		Name:             "ldap",
		URL:              "://",
		UserQueryFilter:  "(userAttr=val)",
		UserQueryAttrs:   ldap.UserQueryAttrs{ID: "uid"},
		GroupQueryFilter: "{{.Invalid}}",
	},
	expectError: `invalid 'group-query-filter' config parameter.*`,
}, {
	about: "malformed group query filter",
	params: ldap.Params{
		Name:             "ldap",
		URL:              "://",
		UserQueryFilter:  "(userAttr=val)",
		UserQueryAttrs:   ldap.UserQueryAttrs{ID: "uid"},
		GroupQueryFilter: "{{.User",
	},
	expectError: `invalid 'group-query-filter' config parameter.*`,
}, {
	about: "invalid group query filter expression",
	params: ldap.Params{
		Name:             "ldap",
		URL:              "://",
		UserQueryFilter:  "(userAttr=val)",
		UserQueryAttrs:   ldap.UserQueryAttrs{ID: "uid"},
		GroupQueryFilter: "(invalid=",
	},
	expectError: `invalid 'group-query-filter' config parameter.*`,
}}

func getSampleLdapDB() ldapDB {
	return ldapDB{{
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
}

func getSampleParams() ldap.Params {
	return ldap.Params{
		Name:             "test",
		URL:              "ldap://localhost",
		DN:               "cn=test,dc=example,dc=com",
		Password:         "pass",
		UserQueryFilter:  "(objectClass=account)",
		UserQueryAttrs:   ldap.UserQueryAttrs{ID: "uid"},
		GroupQueryFilter: "(&(objectClass=groupOfNames)(member={{.User}}))",
	}
}

func (s *ldapSuite) setupIdp(c *qt.C, params ldap.Params, db ldapDB) idp.IdentityProvider {
	i, err := ldap.NewIdentityProvider(params)
	c.Assert(err, qt.Equals, nil)
	ldap.SetLDAP(i, newMockLDAPDialer(db).Dial)
	i.Init(context.TODO(), s.idptest.InitParams(c, idpPrefix))
	return i
}

func (s *ldapSuite) TestNewIdentityProvider(c *qt.C) {
	for _, test := range newTests {
		c.Run(test.about, func(c *qt.C) {
			idp, err := ldap.NewIdentityProvider(test.params)
			if test.expectError == "" {
				c.Assert(err, qt.Equals, nil)
				c.Assert(idp, qt.Not(qt.IsNil))
				return
			}
			c.Assert(err, qt.ErrorMatches, test.expectError)
			c.Assert(idp, qt.IsNil)
		})
	}
}

func (s *ldapSuite) TestName(c *qt.C) {
	idp, err := ldap.NewIdentityProvider(getSampleParams())
	c.Assert(err, qt.Equals, nil)
	c.Assert(idp.Name(), qt.Equals, "test")
}

func (s *ldapSuite) TestDescription(c *qt.C) {
	params := getSampleParams()
	params.Description = "test description"
	idp, err := ldap.NewIdentityProvider(params)
	c.Assert(err, qt.Equals, nil)
	c.Assert(idp.Description(), qt.Equals, "test description")
}

func (s *ldapSuite) TestIconURL(c *qt.C) {
	idp, err := ldap.NewIdentityProvider(getSampleParams())
	c.Assert(err, qt.Equals, nil)
	c.Assert(idp.IconURL(), qt.Equals, "")
}

func (s *ldapSuite) TestAbsoluteIconURL(c *qt.C) {
	params := getSampleParams()
	params.Icon = "https://www.example.com/icon.bmp"
	idp, err := ldap.NewIdentityProvider(params)
	c.Assert(err, qt.Equals, nil)
	c.Assert(idp.IconURL(), qt.Equals, "https://www.example.com/icon.bmp")
}

func (s *ldapSuite) TestRelativeIconURL(c *qt.C) {
	params := getSampleParams()
	params.Icon = "/static/icon.bmp"
	i, err := ldap.NewIdentityProvider(params)
	c.Assert(err, qt.Equals, nil)
	err = i.Init(context.Background(), idp.InitParams{
		Location: "https://www.example.com/candid",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(i.IconURL(), qt.Equals, "https://www.example.com/candid/static/icon.bmp")
}

func (s *ldapSuite) TestDomain(c *qt.C) {
	params := getSampleParams()
	params.Domain = "test domain"
	idp, err := ldap.NewIdentityProvider(params)
	c.Assert(err, qt.Equals, nil)
	c.Assert(idp.Domain(), qt.Equals, "test domain")
}

func (s *ldapSuite) TestInteractive(c *qt.C) {
	idp, err := ldap.NewIdentityProvider(getSampleParams())
	c.Assert(err, qt.Equals, nil)
	c.Assert(idp.Interactive(), qt.Equals, true)
}

func (s *ldapSuite) TestURL(c *qt.C) {
	i, err := ldap.NewIdentityProvider(getSampleParams())
	c.Assert(err, qt.Equals, nil)
	i.Init(context.Background(), idp.InitParams{
		URLPrefix: idpPrefix,
	})
	c.Assert(i.URL("1"), qt.Equals, idpPrefix+"/login?state=1")
}

func (s *ldapSuite) TestHandle(c *qt.C) {
	params := getSampleParams()
	params.Domain = "ldap"
	i := s.setupIdp(c, params, getSampleLdapDB())
	id, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "pass1"))
	c.Assert(err, qt.Equals, nil)
	c.Assert(id.Username, qt.Equals, "user1@ldap")
	s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity(
			"test", "uid=user1,ou=users,dc=example,dc=com"),
		Username: "user1@ldap",
	})
}

func (s *ldapSuite) TestHandleCustomUserFilter(c *qt.C) {
	params := getSampleParams()
	params.UserQueryFilter = "(customAttr=customValue)"
	sampleDB := getSampleLdapDB()
	sampleDB[1]["objectClass"] = []string{"ignored"}
	sampleDB[1]["customAttr"] = []string{"customValue"}
	i := s.setupIdp(c, params, sampleDB)
	id, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "pass1"))
	c.Assert(err, qt.Equals, nil)
	c.Assert(id.Username, qt.Equals, "user1")
	s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity(
			"test", "uid=user1,ou=users,dc=example,dc=com"),
		Username: "user1",
	})
}

func (s *ldapSuite) TestHandleUserDetails(c *qt.C) {
	params := getSampleParams()
	params.UserQueryAttrs.Email = "mail"
	params.UserQueryAttrs.DisplayName = "displayName"
	sampleDB := getSampleLdapDB()
	sampleDB[1]["mail"] = []string{"user1@example.com"}
	sampleDB[1]["displayName"] = []string{"User One"}
	i := s.setupIdp(c, params, sampleDB)
	id, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "pass1"))
	c.Assert(err, qt.Equals, nil)
	c.Assert(id.Username, qt.Equals, "user1")
	s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity(
			"test", "uid=user1,ou=users,dc=example,dc=com"),
		Username: "user1",
		Name:     "User One",
		Email:    "user1@example.com",
	})
}

func (s *ldapSuite) TestHandleUserDetailsCustomIDAttr(c *qt.C) {
	params := getSampleParams()
	params.UserQueryAttrs.ID = "myId"
	sampleDB := getSampleLdapDB()
	sampleDB[1]["uid"] = []string{"ignored"}
	sampleDB[1]["myId"] = []string{"user1"}
	i := s.setupIdp(c, params, sampleDB)
	id, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "pass1"))
	c.Assert(err, qt.Equals, nil)
	c.Assert(id.Username, qt.Equals, "user1")
	s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity(
			"test", "uid=user1,ou=users,dc=example,dc=com"),
		Username: "user1",
	})
}

func (s *ldapSuite) TestHandleWithGroups(c *qt.C) {
	docs := []ldapDoc{{
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
	sampleDB := append(getSampleLdapDB(), docs...)
	i := s.setupIdp(c, getSampleParams(), sampleDB)
	id, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "pass1"))
	c.Assert(err, qt.Equals, nil)
	c.Assert(id.Username, qt.Equals, "user1")
	identity := s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity(
			"test", "uid=user1,ou=users,dc=example,dc=com"),
		Username: "user1",
	})
	groups, err := i.GetGroups(s.idptest.Ctx, identity)
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"group1", "group2"})
}

func (s *ldapSuite) TestHandleCustomGroupFilter(c *qt.C) {
	params := getSampleParams()
	params.GroupQueryFilter = "(&(customAttr=customValue)(user={{.User}}))"
	docs := []ldapDoc{{
		"dn":         {"cn=group1,ou=users,dc=example,dc=com"},
		"customAttr": {"customValue"},
		"cn":         {"group1"},
		"user": {
			"uid=user1,ou=users,dc=example,dc=com",
			"uid=user2,ou=users,dc=example,dc=com",
		},
	}, {
		"dn":         {"cn=group2,ou=users,dc=example,dc=com"},
		"customAttr": {"customValue"},
		"cn":         {"group2"},
		"user":       {"uid=user1,ou=users,dc=example,dc=com"},
	}}
	sampleDB := append(getSampleLdapDB(), docs...)
	i := s.setupIdp(c, params, sampleDB)
	id, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "pass1"))
	c.Assert(err, qt.Equals, nil)
	c.Assert(id.Username, qt.Equals, "user1")
	identity := s.idptest.Store.AssertUser(c, &store.Identity{
		ProviderID: store.MakeProviderIdentity(
			"test", "uid=user1,ou=users,dc=example,dc=com"),
		Username: "user1",
	})
	groups, err := i.GetGroups(s.idptest.Ctx, identity)
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"group1", "group2"})
}

func (s *ldapSuite) TestHandleIncorrectUsername(c *qt.C) {
	i := s.setupIdp(c, getSampleParams(), getSampleLdapDB())
	_, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user-not-there", "wrong"))
	c.Assert(err, qt.ErrorMatches, `invalid username or password`)
}

func (s *ldapSuite) TestHandleFailedLogin(c *qt.C) {
	i := s.setupIdp(c, getSampleParams(), getSampleLdapDB())
	_, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "wrong"))
	c.Assert(err, qt.ErrorMatches, `invalid username or password`)
}

func (s *ldapSuite) TestHandleUserFilterNoMatch(c *qt.C) {
	params := getSampleParams()
	params.UserQueryFilter = "(customAttr=customValue)"
	sampleDB := getSampleLdapDB()
	sampleDB[1]["objectClass"] = []string{"ignored"}
	sampleDB[1]["customAttr"] = []string{"customValue2"}
	i := s.setupIdp(c, params, sampleDB)
	_, err := s.idptest.DoInteractiveLogin(c, i, idpPrefix+"/login", candidtest.PostLoginForm("user1", "pass1"))
	c.Assert(err, qt.ErrorMatches, `user &#34;user1&#34; not found: not found`)
}
