// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package auth_test

import (
	"sort"

	"github.com/juju/aclstore/v2"
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/test"
	"github.com/CanonicalLtd/candid/internal/auth"
	"github.com/CanonicalLtd/candid/internal/candidtest"
	"github.com/CanonicalLtd/candid/store"
)

type authSuite struct {
	candidtest.StoreSuite
	oven                *bakery.Oven
	authorizer          *auth.Authorizer
	context             context.Context
	close               func()
	adminAgentKey       *bakery.KeyPair
	providerGroups      []string
	providerGroupsError error
}

var _ = gc.Suite(&authSuite{})

const identityLocation = "https://identity.test/id"

func (s *authSuite) SetUpTest(c *gc.C) {
	s.StoreSuite.SetUpTest(c)
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
	locator := bakery.NewThirdPartyStore()
	locator.AddInfo(identityLocation, bakery.ThirdPartyInfo{
		PublicKey: key.Public,
		Version:   bakery.LatestVersion,
	})
	s.oven = bakery.NewOven(bakery.OvenParams{
		Key:      key,
		Locator:  locator,
		Location: "identity",
	})
	aclManager, err := aclstore.NewManager(context.Background(), aclstore.Params{
		Store:             s.ACLStore,
		InitialAdminUsers: []string{auth.AdminUsername},
	})
	c.Assert(err, gc.Equals, nil)
	s.context, s.close = s.Store.Context(context.Background())
	s.authorizer, err = auth.New(auth.Params{
		AdminPassword:    "password",
		Location:         identityLocation,
		MacaroonVerifier: s.oven,
		Store:            s.Store,
		IdentityProviders: []idp.IdentityProvider{
			test.NewIdentityProvider(test.Params{
				Name:      "test",
				GetGroups: s.getGroups,
			}),
		},
		ACLManager: aclManager,
	})
	c.Assert(err, gc.Equals, nil)
	s.adminAgentKey, err = bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
	err = s.authorizer.SetAdminPublicKey(s.context, &s.adminAgentKey.Public)
	c.Assert(err, gc.Equals, nil)
}

func (s *authSuite) getGroups(*store.Identity) ([]string, error) {
	return s.providerGroups, s.providerGroupsError
}

func (s *authSuite) TearDownTest(c *gc.C) {
	s.close()
	s.StoreSuite.TearDownTest(c)
}

func (s *authSuite) createIdentity(c *gc.C, username string, pk *bakery.PublicKey, groups ...string) *auth.Identity {
	var pks []bakery.PublicKey
	if pk != nil {
		pks = append(pks, *pk)
	}
	err := s.Store.UpdateIdentity(s.context, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", username),
		Username:   username,
		Groups:     groups,
		PublicKeys: pks,
	}, store.Update{
		store.Username:   store.Set,
		store.Groups:     store.Set,
		store.PublicKeys: store.Set,
	})
	c.Assert(err, gc.Equals, nil)
	id, err := s.authorizer.Identity(s.context, username)
	c.Assert(err, gc.Equals, nil)
	return id
}

func (s authSuite) identityMacaroon(c *gc.C, username string) *bakery.Macaroon {
	m, err := s.oven.NewMacaroon(
		s.context,
		bakery.LatestVersion,
		[]checkers.Caveat{
			candidclient.UserDeclaration(username),
		},
		identchecker.LoginOp,
	)
	c.Assert(err, gc.Equals, nil)
	return m
}

func (s *authSuite) TestAuthorizeWithAdminCredentials(c *gc.C) {
	tests := []struct {
		about              string
		username           string
		password           string
		expectErrorMessage string
	}{{
		about:    "good credentials",
		username: "admin",
		password: "password",
	}, {
		about:              "bad username",
		username:           "not-admin",
		password:           "password",
		expectErrorMessage: "could not determine identity: invalid credentials",
	}, {
		about:              "bad password",
		username:           "admin",
		password:           "not-password",
		expectErrorMessage: "could not determine identity: invalid credentials",
	}}
	for i, test := range tests {
		c.Logf("test %d. %s", i, test.about)
		ctx := context.Background()
		if test.username != "" {
			ctx = auth.ContextWithUserCredentials(ctx, test.username, test.password)
		}
		authInfo, err := s.authorizer.Auth(ctx, nil, identchecker.LoginOp)
		if test.expectErrorMessage != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErrorMessage)
			c.Assert(errgo.Cause(err), gc.Equals, params.ErrUnauthorized)
			continue
		}
		c.Assert(err, gc.Equals, nil)
		c.Assert(authInfo.Identity.Id(), gc.Equals, auth.AdminUsername)
	}
}

func (s *authSuite) TestUserHasPublicKeyCaveat(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	cav := auth.UserHasPublicKeyCaveat(params.Username("test"), &key.Public)
	c.Assert(cav.Namespace, gc.Equals, auth.CheckersNamespace)
	c.Assert(cav.Condition, gc.Matches, "user-has-public-key test .*")
	c.Assert(cav.Location, gc.Equals, "")
}

func (s *authSuite) TestUserHasPublicKeyChecker(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	ctx, close := s.Store.Context(context.Background())
	defer close()
	s.createIdentity(c, "test-user", &key.Public)

	checker := auth.NewChecker(s.authorizer)

	checkCaveat := func(cav checkers.Caveat) error {
		cav = checker.Namespace().ResolveCaveat(cav)
		return checker.CheckFirstPartyCaveat(ctx, cav.Condition)
	}

	err = checkCaveat(auth.UserHasPublicKeyCaveat(params.Username("test-user"), &key.Public))
	c.Assert(err, gc.IsNil)
	// Unknown username
	err = checkCaveat(auth.UserHasPublicKeyCaveat("test2", &key.Public))
	c.Assert(err, gc.ErrorMatches, "caveat.*not satisfied: public key not valid for user")
	// Incorrect public key
	err = checkCaveat(auth.UserHasPublicKeyCaveat("test2", new(bakery.PublicKey)))
	c.Assert(err, gc.ErrorMatches, "caveat.*not satisfied: public key not valid for user")
	// Invalid argument
	err = checkCaveat(checkers.Caveat{
		Namespace: auth.CheckersNamespace,
		Condition: "user-has-public-key test",
	})
	c.Assert(err, gc.ErrorMatches, "caveat.*not satisfied: caveat badly formatted")

	// Invalid public key
	err = checkCaveat(checkers.Caveat{
		Namespace: auth.CheckersNamespace,
		Condition: "user-has-public-key test " + key.Public.String()[1:],
	})
	c.Assert(err, gc.ErrorMatches, `caveat.*not satisfied: invalid public key ".*": .*`)
}

var aclForOpTests = []struct {
	op           bakery.Op
	expect       []string
	expectPublic bool
}{{
	op: op("other", "read"),
}, {
	op:           auth.GlobalOp("read"),
	expect:       []string{auth.AdminUsername},
	expectPublic: false,
}, {
	op:           auth.GlobalOp("verify"),
	expect:       []string{identchecker.Everyone},
	expectPublic: true,
}, {
	op:           auth.GlobalOp("dischargeFor"),
	expect:       []string{auth.AdminUsername},
	expectPublic: false,
}, {
	op:           auth.GlobalOp("login"),
	expect:       []string{identchecker.Everyone},
	expectPublic: true,
}, {
	op:     auth.GlobalOp("createAgent"),
	expect: []string{identchecker.Everyone},
}, {
	op: op("global-foo", "login"),
}, {
	op: auth.GlobalOp("unknown"),
}, {
	op: op("u", "read"),
}, {
	op: auth.UserOp("", "read"),
}, {
	op:     auth.UserOp("bob", "read"),
	expect: []string{"bob", auth.AdminUsername},
}, {
	op:     auth.UserOp("bob", "readAdmin"),
	expect: []string{auth.AdminUsername},
}, {
	op:     auth.UserOp("bob", "writeAdmin"),
	expect: []string{auth.AdminUsername},
}, {
	op:     auth.UserOp("bob", "readGroups"),
	expect: []string{"bob", auth.AdminUsername, auth.GroupListGroup},
}, {
	op:     auth.UserOp("bob", "writeGroups"),
	expect: []string{auth.AdminUsername},
}, {
	op:     auth.UserOp("bob", "readSSHKeys"),
	expect: []string{"bob", auth.AdminUsername, auth.SSHKeyGetterGroup},
}, {
	op:     auth.UserOp("bob", "writeSSHKeys"),
	expect: []string{"bob", auth.AdminUsername},
}}

func (s *authSuite) TestACLForOp(c *gc.C) {
	for i, test := range aclForOpTests {
		c.Logf("test %d: %v", i, test.op)
		sort.Strings(test.expect)
		acl, public, err := auth.AuthorizerACLForOp(s.authorizer, context.Background(), test.op)
		c.Assert(err, gc.IsNil)
		sort.Strings(acl)
		c.Assert(acl, gc.DeepEquals, test.expect)
		c.Assert(public, gc.Equals, test.expectPublic)
	}
}

func (s *authSuite) TestAdminUserGroups(c *gc.C) {
	ctx := auth.ContextWithUserCredentials(context.Background(), "admin", "password")
	authInfo, err := s.authorizer.Auth(ctx, nil, identchecker.LoginOp)
	c.Assert(err, gc.IsNil)
	assertAuthorizedGroups(c, authInfo, nil)
}

func (s *authSuite) TestNonExistentUserGroups(c *gc.C) {
	m := s.identityMacaroon(c, "noone")
	authInfo, err := s.authorizer.Auth(s.context, []macaroon.Slice{{m.M()}}, identchecker.LoginOp)
	c.Assert(err, gc.Equals, nil)
	ident := authInfo.Identity.(*auth.Identity)
	groups, err := ident.Groups(s.context)
	c.Assert(err, gc.ErrorMatches, `user noone not found`)
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrNotFound)
	c.Assert(groups, gc.IsNil)
}

func (s *authSuite) TestExistingUserGroups(c *gc.C) {
	// good identity
	s.createIdentity(c, "test", nil, "test-group1", "test-group2")
	m := s.identityMacaroon(c, "test")
	authInfo, err := s.authorizer.Auth(s.context, []macaroon.Slice{{m.M()}}, identchecker.LoginOp)
	c.Assert(err, gc.Equals, nil)
	assertAuthorizedGroups(c, authInfo, []string{"test-group1", "test-group2"})
}

func assertAuthorizedGroups(c *gc.C, authInfo *identchecker.AuthInfo, expectGroups []string) {
	c.Assert(authInfo.Identity, gc.NotNil)
	ident := authInfo.Identity.(*auth.Identity)
	groups, err := ident.Groups(context.Background())
	c.Assert(err, gc.IsNil)
	c.Assert(groups, gc.DeepEquals, expectGroups)
}

var identityAllowTests = []struct {
	about string

	// groups holds the groups the user is a member of.
	groups []string

	// externalGroups holds the groups that will
	// be returned by the external group getter.
	externalGroups []string

	// externalGroupsError holds an error to be returned by externalGroups.
	externalGroupsError error

	// ACL holds the ACL that's being checked.
	acl []string

	// expectAllowed holds whether the access to the ACL
	// should be granted.
	expectAllowed bool

	// expectError holds the expected error from the Allow call.
	expectError string
}{{
	about:         "everyone is allowed even with no store",
	acl:           []string{"everyone"},
	expectAllowed: true,
}, {
	about:         "user is allowed even with no store",
	acl:           []string{"testuser"},
	expectAllowed: true,
}, {
	about:         "empty ACL doesn't require store",
	expectAllowed: false,
}, {
	about:         "user is allowed if they're in the expected group internally",
	acl:           []string{"somegroup"},
	groups:        []string{"x", "somegroup"},
	expectAllowed: true,
}, {
	about:          "user is allowed if they're in the expected group externally",
	acl:            []string{"somegroup"},
	externalGroups: []string{"x", "somegroup"},
	expectAllowed:  true,
}, {
	about:         "user is not allowed if they're not in the expected group",
	acl:           []string{"somegroup"},
	groups:        []string{"x"},
	expectAllowed: false,
}, {
	about:               "error from external groups is ignored",
	acl:                 []string{"somegroup"},
	groups:              []string{"somegroup"},
	externalGroupsError: errgo.New("some error"),
	expectAllowed:       true,
}}

func (s *authSuite) TestIdentityAllow(c *gc.C) {
	for i, test := range identityAllowTests {
		c.Logf("test %d: %v", i, test.about)
		s.providerGroups = test.externalGroups
		s.providerGroupsError = test.externalGroupsError
		id := s.createIdentity(c, "testuser", nil, test.groups...)
		ok, err := id.Allow(s.context, test.acl)
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			c.Assert(ok, gc.Equals, false)
		} else {
			c.Assert(err, gc.Equals, nil)
			c.Assert(ok, gc.Equals, test.expectAllowed)
		}
	}
}

func (s *authSuite) TestAuthorizeMacaroonRequired(c *gc.C) {
	authInfo, err := s.authorizer.Auth(s.context, nil, identchecker.LoginOp)
	c.Assert(err, gc.ErrorMatches, `macaroon discharge required: authentication required`)
	c.Assert(authInfo, gc.IsNil)
	c.Assert(errgo.Cause(err), gc.FitsTypeOf, (*bakery.DischargeRequiredError)(nil))
	derr := errgo.Cause(err).(*bakery.DischargeRequiredError)
	c.Assert(derr.Ops, jc.DeepEquals, []bakery.Op{identchecker.LoginOp})
	c.Assert(derr.Caveats, jc.DeepEquals, []checkers.Caveat{{Condition: "need-declared username is-authenticated-user", Location: "https://identity.test/id"}})
}

func op(entity, action string) bakery.Op {
	return bakery.Op{
		Entity: entity,
		Action: action,
	}
}

type testGroupGetter struct {
	groups []string
	error  error
}

func (t testGroupGetter) GetGroups(_ context.Context, id *store.Identity) ([]string, error) {
	return t.groups, t.error
}
