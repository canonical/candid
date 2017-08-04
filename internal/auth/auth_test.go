// Copyright 2014 Canonical Ltd.

package auth_test

import (
	"sort"
	"time"

	"github.com/juju/idmclient"
	"github.com/juju/idmclient/params"
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	macaroon "gopkg.in/macaroon.v2-unstable"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/auth"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

type authSuite struct {
	testing.IsolatedMgoSuite
	pool       *store.Pool
	oven       *bakery.Oven
	authorizer *auth.Authorizer
}

var _ = gc.Suite(&authSuite{})

const identityLocation = "https://identity.test/id"

func (s *authSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.pool, err = store.NewPool(
		s.Session.Copy().DB("idm-test"),
		store.StoreParams{},
	)
	c.Assert(err, gc.IsNil)
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
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
	s.authorizer = auth.New(auth.Params{
		AdminUsername:   "admin",
		AdminPassword:   "password",
		Location:        identityLocation,
		MacaroonOpStore: s.oven,
	})
}

func (s *authSuite) TearDownTest(c *gc.C) {
	s.pool.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

func (s *authSuite) createIdentity(c *gc.C, doc *mongodoc.Identity) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	if doc.ExternalID != "" {
		err := store.UpsertUser(doc)
		c.Assert(err, gc.IsNil)
	} else {
		err := store.UpsertAgent(doc)
		c.Assert(err, gc.IsNil)
	}
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
		authInfo, err := s.authorizer.Auth(ctx, nil, bakery.LoginOp)
		if test.expectErrorMessage != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErrorMessage)
			c.Assert(errgo.Cause(err), gc.Equals, params.ErrUnauthorized)
			continue
		}
		c.Assert(err, gc.Equals, nil)
		c.Assert(authInfo.Identity, gc.Equals, auth.Identity(auth.AdminUsername))
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

	s.createIdentity(c, &mongodoc.Identity{
		Username: "test@admin",
		Owner:    "admin",
		PublicKeys: []mongodoc.PublicKey{
			{Key: key.Public.Key[:]},
		},
	})

	checker := auth.NewChecker()

	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)
	ctx := auth.ContextWithStore(context.Background(), st)
	checkCaveat := func(cav checkers.Caveat) error {
		cav = checker.Namespace().ResolveCaveat(cav)
		return checker.CheckFirstPartyCaveat(ctx, cav.Condition)
	}

	err = checkCaveat(auth.UserHasPublicKeyCaveat(params.Username("test@admin"), &key.Public))
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

	// Invalid username
	err = checkCaveat(auth.UserHasPublicKeyCaveat("a=b", new(bakery.PublicKey)))
	c.Assert(err, gc.ErrorMatches, `caveat.*not satisfied: illegal username "a=b"`)

	// Invalid public key
	err = checkCaveat(checkers.Caveat{
		Namespace: auth.CheckersNamespace,
		Condition: "user-has-public-key test " + key.Public.String()[1:],
	})
	c.Assert(err, gc.ErrorMatches, `caveat.*not satisfied: invalid public key ".*": .*`)
}

var aclForOpTests = []struct {
	op     bakery.Op
	expect []string
}{{
	op: op("other", "read"),
}, {
	op:     auth.GlobalOp("read"),
	expect: auth.AdminACL,
}, {
	op:     auth.GlobalOp("verify"),
	expect: []string{bakery.Everyone},
}, {
	op:     auth.GlobalOp("dischargeFor"),
	expect: auth.AdminACL,
}, {
	op:     auth.GlobalOp("login"),
	expect: []string{bakery.Everyone},
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
	expect: append([]string{"bob"}, auth.AdminACL...),
}, {
	op:     auth.UserOp("bob", "createAgent"),
	expect: append([]string{"+create-agent@bob"}, auth.AdminACL...),
}, {
	op:     auth.UserOp("bob", "readAdmin"),
	expect: auth.AdminACL,
}, {
	op:     auth.UserOp("bob", "writeAdmin"),
	expect: auth.AdminACL,
}, {
	op:     auth.UserOp("bob", "readGroups"),
	expect: append([]string{"bob", auth.GroupListGroup}, auth.AdminACL...),
}, {
	op:     auth.UserOp("bob", "writeGroups"),
	expect: auth.AdminACL,
}, {
	op:     auth.UserOp("bob", "readSSHKeys"),
	expect: append([]string{"bob", auth.SSHKeyGetterGroup}, auth.AdminACL...),
}, {
	op:     auth.UserOp("bob", "writeSSHKeys"),
	expect: append([]string{"bob"}, auth.AdminACL...),
}}

func (s *authSuite) TestACLForOp(c *gc.C) {
	for i, test := range aclForOpTests {
		c.Logf("test %d: %v", i, test.op)
		sort.Strings(test.expect)
		acl, err := auth.AuthorizerACLForOp(s.authorizer, context.Background(), test.op)
		c.Assert(err, gc.IsNil)
		sort.Strings(acl)
		c.Assert(acl, gc.DeepEquals, test.expect)
	}
}

func (s *authSuite) TestAdminUserGroups(c *gc.C) {
	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)

	ctx := auth.ContextWithUserCredentials(context.Background(), "admin", "password")
	authInfo, err := s.authorizer.Auth(ctx, nil, bakery.LoginOp)
	c.Assert(err, gc.IsNil)
	assertAuthorizedGroups(c, st, authInfo, []string{})
}

func (s *authSuite) TestNonExistentUserGroups(c *gc.C) {
	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)

	m, err := s.oven.NewMacaroon(
		context.Background(),
		bakery.LatestVersion,
		time.Now().Add(time.Minute), []checkers.Caveat{
			idmclient.UserDeclaration("noone"),
		},
		bakery.LoginOp,
	)
	c.Assert(err, gc.IsNil)
	authInfo, err := s.authorizer.Auth(context.Background(), []macaroon.Slice{{m.M()}}, bakery.LoginOp)
	c.Assert(err, gc.IsNil)
	ident := authInfo.Identity.(auth.Identity)
	ctx := auth.ContextWithStore(context.Background(), st)
	groups, err := ident.Groups(ctx)
	c.Assert(err, gc.ErrorMatches, `user "noone" not found: not found`)
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrNotFound)
	c.Assert(groups, gc.IsNil)
}

func (s *authSuite) TestExistingUserGroups(c *gc.C) {
	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)
	// good identity
	s.createIdentity(c, &mongodoc.Identity{
		Username:   "test",
		ExternalID: "https://example.com/test",
		Groups:     []string{"test-group1", "test-group2"},
	})
	m, err := s.oven.NewMacaroon(
		context.Background(),
		bakery.LatestVersion,
		time.Now().Add(time.Minute),
		[]checkers.Caveat{
			idmclient.UserDeclaration("test"),
		},
		bakery.LoginOp,
	)
	c.Assert(err, gc.IsNil)
	authInfo, err := s.authorizer.Auth(context.Background(), []macaroon.Slice{{m.M()}}, bakery.LoginOp)
	c.Assert(err, gc.IsNil)
	assertAuthorizedGroups(c, st, authInfo, []string{"test-group1", "test-group2"})
}

func assertAuthorizedGroups(c *gc.C, st *store.Store, authInfo *bakery.AuthInfo, expectGroups []string) {
	c.Assert(authInfo.Identity, gc.NotNil)
	ident := authInfo.Identity.(auth.Identity)
	ctx := auth.ContextWithStore(context.Background(), st)
	groups, err := ident.Groups(ctx)
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

	// withStore holds whether a store instance should
	// be attached to the context.
	withStore bool

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
	about:       "error when there's no store and result is not trivial",
	acl:         []string{"somegroup"},
	expectError: "no store found in context",
}, {
	about:         "empty ACL doesn't require store",
	expectAllowed: false,
}, {
	about:         "user is allowed if they're in the expected group internally",
	acl:           []string{"somegroup"},
	groups:        []string{"x", "somegroup"},
	withStore:     true,
	expectAllowed: true,
}, {
	about:          "user is allowed if they're in the expected group externally",
	acl:            []string{"somegroup"},
	externalGroups: []string{"x", "somegroup"},
	withStore:      true,
	expectAllowed:  true,
}, {
	about:         "user is not allowed if they're not in the expected group",
	acl:           []string{"somegroup"},
	groups:        []string{"x"},
	withStore:     true,
	expectAllowed: false,
}, {
	about:               "error from external groups is ignored",
	acl:                 []string{"somegroup"},
	groups:              []string{"somegroup"},
	externalGroupsError: errgo.New("some error"),
	withStore:           true,
	expectAllowed:       true,
}}

func (s *authSuite) TestIdentityAllow(c *gc.C) {
	var externalGroups []string
	var externalGroupsError error

	pool, err := store.NewPool(
		s.Session.Copy().DB("store-launchpad-tests"),
		store.StoreParams{
			ExternalGroupGetter: externalGroupGetterFunc(func(id string) ([]string, error) {
				c.Check(id, gc.Equals, "testuser-external-id")
				return externalGroups, externalGroupsError
			})},
	)
	c.Assert(err, gc.IsNil)
	defer pool.Close()
	st := pool.GetNoLimit()
	defer pool.Put(st)
	// Add an identity to the store.
	err = st.UpsertUser(&mongodoc.Identity{
		Username:   "testuser",
		ExternalID: "testuser-external-id",
		Email:      "testuser@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
		},
	})
	c.Assert(err, gc.IsNil)

	for i, test := range identityAllowTests {
		c.Logf("test %d: %v", i, test.about)
		err = st.UpdateIdentity("testuser", bson.D{{"$set", bson.D{{"groups", test.groups}}}})
		c.Assert(err, gc.IsNil)
		externalGroups, externalGroupsError = test.externalGroups, test.externalGroupsError
		id := auth.Identity("testuser")
		ctx := context.Background()
		if test.withStore {
			ctx = auth.ContextWithStore(ctx, st)
		}
		ok, err := id.Allow(ctx, test.acl)
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			c.Assert(ok, gc.Equals, false)
		} else {
			c.Assert(err, gc.IsNil)
			c.Assert(ok, gc.Equals, test.expectAllowed)
		}
	}
}

func (s *authSuite) TestIdentityGroups(c *gc.C) {
	pool, err := store.NewPool(
		s.Session.Copy().DB("store-launchpad-tests"),
		store.StoreParams{
			ExternalGroupGetter: externalGroupGetterFunc(func(id string) ([]string, error) {
				return []string{"extgroup1", "extgroup2", "group1"}, nil
			}),
		},
	)
	c.Assert(err, gc.IsNil)
	defer pool.Close()
	st := pool.GetNoLimit()
	defer pool.Put(st)
	err = st.UpsertUser(&mongodoc.Identity{
		Username:   "testuser",
		ExternalID: "testuser-external-id",
		Email:      "testuser@example.com",
		FullName:   "Test User",
		Groups: []string{
			"group1",
			"group2",
		},
	})
	c.Assert(err, gc.IsNil)
	id := auth.Identity("testuser")
	ctx := auth.ContextWithStore(context.Background(), st)
	groups, err := id.Groups(ctx)
	c.Assert(err, gc.IsNil)
	c.Assert(groups, gc.DeepEquals, []string{"extgroup1", "extgroup2", "group1", "group2"})
}

func (s *authSuite) TestIdentityGroupsForAgent(c *gc.C) {
	pool, err := store.NewPool(
		s.Session.Copy().DB("store-launchpad-tests"),
		store.StoreParams{
			ExternalGroupGetter: externalGroupGetterFunc(func(id string) ([]string, error) {
				if id != "testuser-external-id" {
					return nil, params.ErrNotFound
				}
				return []string{"extgroup1", "extgroup2", "group1"}, nil
			}),
		},
	)
	c.Assert(err, gc.IsNil)
	defer pool.Close()
	st := pool.GetNoLimit()
	defer pool.Put(st)
	err = st.UpsertUser(&mongodoc.Identity{
		Username:   "testuser",
		ExternalID: "testuser-external-id",
		Email:      "testuser@example.com",
		FullName:   "Test User",
		Groups: []string{
			"group1",
			"group2",
		},
	})
	c.Assert(err, gc.IsNil)
	err = st.UpsertAgent(&mongodoc.Identity{
		Username: "agent@testuser",
		Owner:    "testuser",
		Groups: []string{
			"extgroup2",
			"group1",
			"group2",
			"group3",
		},
	})
	c.Assert(err, gc.IsNil)
	id := auth.Identity("agent@testuser")
	ctx := auth.ContextWithStore(context.Background(), st)
	groups, err := id.Groups(ctx)
	c.Assert(err, gc.IsNil)
	c.Assert(groups, gc.DeepEquals, []string{"extgroup2", "group1", "group2"})
}

type externalGroupGetterFunc func(string) ([]string, error)

func (f externalGroupGetterFunc) GetGroups(id string) ([]string, error) {
	return f(id)
}

func (s *authSuite) TestAuthorizeMacaroonRequired(c *gc.C) {
	authInfo, err := s.authorizer.Auth(context.Background(), nil, bakery.LoginOp)
	c.Assert(err, gc.ErrorMatches, `macaroon discharge required: authentication required`)
	c.Assert(authInfo, gc.IsNil)
	c.Assert(errgo.Cause(err), gc.FitsTypeOf, (*bakery.DischargeRequiredError)(nil))
	derr := errgo.Cause(err).(*bakery.DischargeRequiredError)
	c.Assert(derr.Ops, jc.DeepEquals, []bakery.Op{bakery.LoginOp})
	c.Assert(derr.Caveats, jc.DeepEquals, []checkers.Caveat{{Condition: "need-declared username is-authenticated-user", Location: "https://identity.test/id"}})
}

func op(entity, action string) bakery.Op {
	return bakery.Op{
		Entity: entity,
		Action: action,
	}
}
