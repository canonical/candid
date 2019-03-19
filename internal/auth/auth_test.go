// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package auth_test

import (
	"context"
	"fmt"
	"sort"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"github.com/juju/aclstore/v2"
	"gopkg.in/CanonicalLtd/candidclient.v1"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/static"
	"github.com/CanonicalLtd/candid/internal/auth"
	"github.com/CanonicalLtd/candid/internal/candidtest"
	"github.com/CanonicalLtd/candid/store"
)

func TestAuth(t *testing.T) {
	qtsuite.Run(qt.New(t), &authSuite{})
}

type authSuite struct {
	store *candidtest.Store

	oven          *bakery.Oven
	authorizer    *auth.Authorizer
	context       context.Context
	adminAgentKey *bakery.KeyPair
}

const identityLocation = "https://identity.test/id"

func (s *authSuite) Init(c *qt.C) {
	s.store = candidtest.NewStore()

	key, err := bakery.GenerateKey()
	c.Assert(err, qt.Equals, nil)
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
		Store:             s.store.ACLStore,
		InitialAdminUsers: []string{auth.AdminUsername},
	})
	c.Assert(err, qt.Equals, nil)
	ctx, close := s.store.Store.Context(context.Background())
	c.Defer(close)
	s.context = ctx
	s.authorizer, err = auth.New(auth.Params{
		AdminPassword:    "password",
		Location:         identityLocation,
		MacaroonVerifier: s.oven,
		Store:            s.store.Store,
		IdentityProviders: []idp.IdentityProvider{
			static.NewIdentityProvider(static.Params{
				Name: "test",
				Users: map[string]static.UserInfo{
					"testuser": {
						Password: "testpass",
						Groups:   []string{"somegroup"},
					},
				},
			}),
		},
		ACLManager: aclManager,
	})
	c.Assert(err, qt.Equals, nil)
	s.adminAgentKey, err = bakery.GenerateKey()
	c.Assert(err, qt.Equals, nil)
	err = s.authorizer.SetAdminPublicKey(s.context, &s.adminAgentKey.Public)
	c.Assert(err, qt.Equals, nil)
}

func (s *authSuite) createIdentity(c *qt.C, username string, pk *bakery.PublicKey, groups ...string) *auth.Identity {
	var pks []bakery.PublicKey
	if pk != nil {
		pks = append(pks, *pk)
	}
	err := s.store.Store.UpdateIdentity(s.context, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", username),
		Username:   username,
		Groups:     groups,
		PublicKeys: pks,
	}, store.Update{
		store.Username:   store.Set,
		store.Groups:     store.Set,
		store.PublicKeys: store.Set,
	})
	c.Assert(err, qt.Equals, nil)
	id, err := s.authorizer.Identity(s.context, username)
	c.Assert(err, qt.Equals, nil)
	return id
}

func (s authSuite) identityMacaroon(c *qt.C, username string) *bakery.Macaroon {
	m, err := s.oven.NewMacaroon(
		s.context,
		bakery.LatestVersion,
		[]checkers.Caveat{
			candidclient.UserDeclaration(username),
		},
		identchecker.LoginOp,
	)
	c.Assert(err, qt.Equals, nil)
	return m
}

func (s *authSuite) TestAuthorizeWithAdminCredentials(c *qt.C) {
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
	for _, test := range tests {
		c.Run(test.about, func(c *qt.C) {
			ctx := context.Background()
			if test.username != "" {
				ctx = auth.ContextWithUserCredentials(ctx, test.username, test.password)
			}
			authInfo, err := s.authorizer.Auth(ctx, nil, identchecker.LoginOp)
			if test.expectErrorMessage != "" {
				c.Assert(err, qt.ErrorMatches, test.expectErrorMessage)
				c.Assert(errgo.Cause(err), qt.Equals, params.ErrUnauthorized)
				return
			}
			c.Assert(err, qt.Equals, nil)
			c.Assert(authInfo.Identity.Id(), qt.Equals, auth.AdminUsername)
		})
	}
}

func (s *authSuite) TestUserHasPublicKeyCaveat(c *qt.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, qt.Equals, nil)
	cav := auth.UserHasPublicKeyCaveat(params.Username("test"), &key.Public)
	c.Assert(cav.Namespace, qt.Equals, auth.CheckersNamespace)
	c.Assert(cav.Condition, qt.Matches, "user-has-public-key test .*")
	c.Assert(cav.Location, qt.Equals, "")
}

func (s *authSuite) TestUserHasPublicKeyChecker(c *qt.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, qt.Equals, nil)
	ctx, close := s.store.Store.Context(context.Background())
	defer close()
	s.createIdentity(c, "test-user", &key.Public)

	checker := auth.NewChecker(s.authorizer)

	checkCaveat := func(cav checkers.Caveat) error {
		cav = checker.Namespace().ResolveCaveat(cav)
		return checker.CheckFirstPartyCaveat(ctx, cav.Condition)
	}

	err = checkCaveat(auth.UserHasPublicKeyCaveat(params.Username("test-user"), &key.Public))
	c.Assert(err, qt.Equals, nil)
	// Unknown username
	err = checkCaveat(auth.UserHasPublicKeyCaveat("test2", &key.Public))
	c.Assert(err, qt.ErrorMatches, "caveat.*not satisfied: public key not valid for user")
	// Incorrect public key
	err = checkCaveat(auth.UserHasPublicKeyCaveat("test2", new(bakery.PublicKey)))
	c.Assert(err, qt.ErrorMatches, "caveat.*not satisfied: public key not valid for user")
	// Invalid argument
	err = checkCaveat(checkers.Caveat{
		Namespace: auth.CheckersNamespace,
		Condition: "user-has-public-key test",
	})
	c.Assert(err, qt.ErrorMatches, "caveat.*not satisfied: caveat badly formatted")

	// Invalid public key
	err = checkCaveat(checkers.Caveat{
		Namespace: auth.CheckersNamespace,
		Condition: "user-has-public-key test " + key.Public.String()[1:],
	})
	c.Assert(err, qt.ErrorMatches, `caveat.*not satisfied: invalid public key ".*": .*`)
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

func (s *authSuite) TestACLForOp(c *qt.C) {
	for _, test := range aclForOpTests {
		c.Run(fmt.Sprintf("%s-%s", test.op.Entity, test.op.Action), func(c *qt.C) {
			sort.Strings(test.expect)
			acl, public, err := auth.AuthorizerACLForOp(s.authorizer, context.Background(), test.op)
			c.Assert(err, qt.Equals, nil)
			sort.Strings(acl)
			c.Assert(acl, qt.DeepEquals, test.expect)
			c.Assert(public, qt.Equals, test.expectPublic)
		})
	}
}

func (s *authSuite) TestAdminUserGroups(c *qt.C) {
	ctx := auth.ContextWithUserCredentials(context.Background(), "admin", "password")
	authInfo, err := s.authorizer.Auth(ctx, nil, identchecker.LoginOp)
	c.Assert(err, qt.Equals, nil)
	assertAuthorizedGroups(c, authInfo, nil)
}

func (s *authSuite) TestNonExistentUserGroups(c *qt.C) {
	m := s.identityMacaroon(c, "noone")
	authInfo, err := s.authorizer.Auth(s.context, []macaroon.Slice{{m.M()}}, identchecker.LoginOp)
	c.Assert(err, qt.Equals, nil)
	ident := authInfo.Identity.(*auth.Identity)
	groups, err := ident.Groups(s.context)
	c.Assert(err, qt.ErrorMatches, `user noone not found`)
	c.Assert(errgo.Cause(err), qt.Equals, params.ErrNotFound)
	c.Assert(groups, qt.IsNil)
}

func (s *authSuite) TestExistingUserGroups(c *qt.C) {
	// good identity
	s.createIdentity(c, "test", nil, "test-group1", "test-group2")
	m := s.identityMacaroon(c, "test")
	authInfo, err := s.authorizer.Auth(s.context, []macaroon.Slice{{m.M()}}, identchecker.LoginOp)
	c.Assert(err, qt.Equals, nil)
	assertAuthorizedGroups(c, authInfo, []string{"test-group1", "test-group2"})
}

func assertAuthorizedGroups(c *qt.C, authInfo *identchecker.AuthInfo, expectGroups []string) {
	c.Assert(authInfo.Identity, qt.Not(qt.IsNil))
	ident := authInfo.Identity.(*auth.Identity)
	groups, err := ident.Groups(context.Background())
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, expectGroups)
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
	about:         "user is allowed if they're in the expected group externally",
	acl:           []string{"somegroup"},
	expectAllowed: true,
}, {
	about:         "user is not allowed if they're not in the expected group",
	acl:           []string{"othergroup"},
	groups:        []string{"somegroup"},
	expectAllowed: false,
}}

func (s *authSuite) TestIdentityAllow(c *qt.C) {
	for _, test := range identityAllowTests {
		c.Run(test.about, func(c *qt.C) {
			id := s.createIdentity(c, "testuser", nil, test.groups...)
			ok, err := id.Allow(s.context, test.acl)
			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				c.Assert(ok, qt.Equals, false)
			} else {
				c.Assert(err, qt.Equals, nil)
				c.Assert(ok, qt.Equals, test.expectAllowed)
			}
		})
	}
}

func (s *authSuite) TestAuthorizeMacaroonRequired(c *qt.C) {
	authInfo, err := s.authorizer.Auth(s.context, nil, identchecker.LoginOp)
	c.Assert(err, qt.ErrorMatches, `macaroon discharge required: authentication required`)
	c.Assert(authInfo, qt.IsNil)
	cause := errgo.Cause(err)
	derr, ok := cause.(*bakery.DischargeRequiredError)
	if !ok {
		c.Fatalf("error %#v (cause type %T) is not DischargeRequiredError", err, cause)
	}
	c.Assert(derr.Ops, qt.DeepEquals, []bakery.Op{identchecker.LoginOp})
	c.Assert(derr.Caveats, qt.DeepEquals, []checkers.Caveat{{Condition: "need-declared username is-authenticated-user", Location: "https://identity.test/id"}})
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
