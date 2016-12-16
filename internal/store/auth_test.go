// Copyright 2014 Canonical Ltd.

package store_test

import (
	"net/http"

	"github.com/juju/idmclient/params"
	"github.com/juju/testing"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

type authSuite struct {
	testing.IsolatedMgoSuite
	pool *store.Pool
}

var _ = gc.Suite(&authSuite{})

const identityLocation = "https://identity.test/id"

func (s *authSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.pool, err = store.NewPool(
		s.Session.Copy().DB("idm-test"),
		store.StoreParams{
			AuthUsername: "test-admin",
			AuthPassword: "open sesame",
			Location:     identityLocation,
			PrivateAddr:  "localhost",
		},
	)
	c.Assert(err, gc.IsNil)
}

func (s *authSuite) TearDownTest(c *gc.C) {
	s.pool.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

func (s *authSuite) createIdentity(c *gc.C, doc *mongodoc.Identity) (uuid string) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	if doc.ExternalID != "" {
		err := store.UpsertUser(doc)
		c.Assert(err, gc.IsNil)
	} else {
		err := store.UpsertAgent(doc)
		c.Assert(err, gc.IsNil)
	}
	return doc.UUID
}

func (s *authSuite) TestCheckAdminCredentials(c *gc.C) {
	tests := []struct {
		about              string
		header             http.Header
		expectErrorMessage string
	}{{
		about: "good credentials",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1hZG1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expectErrorMessage: "",
	}, {
		about: "bad username",
		header: http.Header{
			"Authorization": []string{"Basic eGVzdC1hZG1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expectErrorMessage: "invalid credentials",
	}, {
		about: "bad password",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1hZG1pbjpvcGVuIHNlc2FtAQ=="},
		},
		expectErrorMessage: "invalid credentials",
	}, {
		about: "incorrect type",
		header: http.Header{
			"Authorization": []string{"Digest dGVzdC1hZG1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expectErrorMessage: "unauthorized: invalid or missing HTTP auth header",
	}, {
		about: "empty authorization",
		header: http.Header{
			"Authorization": []string{""},
		},
		expectErrorMessage: "unauthorized: invalid or missing HTTP auth header",
	}, {
		about:              "no authorization",
		header:             http.Header{},
		expectErrorMessage: params.ErrNoAdminCredsProvided.Error(),
	}, {
		about: "invalid base64",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1h<>1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expectErrorMessage: "unauthorized: invalid HTTP auth encoding",
	}, {
		about: "no colon",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1hZG1pbg=="},
		},
		expectErrorMessage: "unauthorized: invalid HTTP auth contents",
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		store := s.pool.GetNoLimit()
		defer s.pool.Put(store)
		obtained := store.CheckAdminCredentials(&http.Request{
			Header: test.header,
		})
		if test.expectErrorMessage == "" {
			c.Assert(obtained, gc.Equals, nil)
		} else {
			c.Assert(obtained.Error(), gc.Equals, test.expectErrorMessage)
		}
	}
}

func (s *authSuite) TestUserHasPublicKeyCaveat(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	cav := store.UserHasPublicKeyCaveat(params.Username("test"), &key.Public)
	c.Assert(cav.Namespace, gc.Equals, store.CheckersNamespace)
	c.Assert(cav.Condition, gc.Matches, "user-has-public-key test .*")
	c.Assert(cav.Location, gc.Equals, "")
}

func (s *authSuite) TestUserHasPublicKeyChecker(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)

	s.createIdentity(c, &mongodoc.Identity{
		Username: "test",
		Owner:    "admin",
		PublicKeys: []mongodoc.PublicKey{
			{Key: key.Public.Key[:]},
		},
	})

	checker := store.NewChecker()

	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)
	ctx := store.ContextWithStore(context.Background(), st)
	checkCaveat := func(cav checkers.Caveat) error {
		cav = checker.Namespace().ResolveCaveat(cav)
		return checker.CheckFirstPartyCaveat(ctx, cav.Condition)
	}

	err = checkCaveat(store.UserHasPublicKeyCaveat(params.Username("test"), &key.Public))
	c.Assert(err, gc.IsNil)
	// Unknown username
	err = checkCaveat(store.UserHasPublicKeyCaveat("test2", &key.Public))
	c.Assert(err, gc.ErrorMatches, "caveat.*not satisfied: public key not valid for user")
	// Incorrect public key
	err = checkCaveat(store.UserHasPublicKeyCaveat("test2", new(bakery.PublicKey)))
	c.Assert(err, gc.ErrorMatches, "caveat.*not satisfied: public key not valid for user")
	// Invalid argument
	err = checkCaveat(checkers.Caveat{
		Namespace: store.CheckersNamespace,
		Condition: "user-has-public-key test",
	})
	c.Assert(err, gc.ErrorMatches, "caveat.*not satisfied: caveat badly formatted")

	// Invalid username
	err = checkCaveat(store.UserHasPublicKeyCaveat("a=b", new(bakery.PublicKey)))
	c.Assert(err, gc.ErrorMatches, `caveat.*not satisfied: illegal username "a=b"`)

	// Invalid public key
	err = checkCaveat(checkers.Caveat{
		Namespace: store.CheckersNamespace,
		Condition: "user-has-public-key test " + key.Public.String()[1:],
	})
	c.Assert(err, gc.ErrorMatches, `caveat.*not satisfied: invalid public key ".*": .*`)
}

//
//func (s *authSuite) TestGroupsFromRequest(c *gc.C) {
//	testChecker := checkers.OperationChecker("test")
//	store := s.pool.GetNoLimit()
//	defer s.pool.Put(store)
//
//	// Get the groups for the admin user
//	req, err := http.NewRequest("GET", "", nil)
//	c.Assert(err, gc.IsNil)
//	req.SetBasicAuth("test-admin", "open sesame")
//	groups, err := store.GroupsFromRequest(testChecker, req)
//	c.Assert(err, gc.IsNil)
//	c.Assert(len(groups), gc.Equals, 1)
//	c.Assert(groups[0], gc.Equals, "admin@idm")
//
//	// Incorrect admin credentials
//	req, err = http.NewRequest("GET", "", nil)
//	c.Assert(err, gc.IsNil)
//	req.SetBasicAuth("test-admin", "open simsim")
//	groups, err = store.GroupsFromRequest(testChecker, req)
//	c.Assert(len(groups), gc.Equals, 0)
//	c.Assert(errgo.Cause(err), gc.Equals, params.ErrUnauthorized)
//
//	// Request with no credentials (discharge required)
//	req, err = http.NewRequest("GET", "http://example.com/v1/test", nil)
//	c.Assert(err, gc.IsNil)
//	groups, err = store.GroupsFromRequest(testChecker, req)
//	c.Assert(len(groups), gc.Equals, 0)
//	herr, ok := err.(*httpbakery.Error)
//	c.Assert(ok, gc.Equals, true, gc.Commentf("unexpected error %s", err))
//	c.Assert(herr.Code, gc.Equals, httpbakery.ErrDischargeRequired)
//	c.Assert(herr.Info.MacaroonPath, gc.Equals, "../")
//	c.Assert(herr.Info.Macaroon, gc.Not(gc.IsNil))
//	c.Assert(herr.Info.CookieNameSuffix, gc.Equals, "idm")
//	var foundThirdParty bool
//	for _, cav := range herr.Info.Macaroon.Caveats() {
//		if cav.Location == "" {
//			continue
//		}
//		c.Assert(cav.Location, gc.Equals, identityLocation)
//		foundThirdParty = true
//	}
//	c.Assert(foundThirdParty, gc.Equals, true)
//
//	// Non-existent identity
//	m, err := store.Service.NewMacaroon(bakery.LatestVersion, []checkers.Caveat{
//		checkers.DeclaredCaveat("username", "test2"),
//	})
//	c.Assert(err, gc.IsNil)
//	req, err = http.NewRequest("GET", "", nil)
//	c.Assert(err, gc.IsNil)
//	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
//	c.Assert(err, gc.IsNil)
//	req.AddCookie(cookie)
//	groups, err = store.GroupsFromRequest(testChecker, req)
//	c.Assert(len(groups), gc.Equals, 0)
//	c.Assert(errgo.Cause(err), gc.Equals, params.ErrNotFound)
//
//	// good identity
//	s.createIdentity(c, &mongodoc.Identity{
//		Username:   "test",
//		ExternalID: "https://example.com/test",
//		Groups:     []string{"test-group1", "test-group2"},
//	})
//	m, err = store.Service.NewMacaroon(bakery.LatestVersion, []checkers.Caveat{
//		checkers.DeclaredCaveat("username", "test"),
//	})
//	req, err = http.NewRequest("GET", "", nil)
//	c.Assert(err, gc.IsNil)
//	cookie, err = httpbakery.NewCookie(macaroon.Slice{m})
//	c.Assert(err, gc.IsNil)
//	req.AddCookie(cookie)
//	groups, err = store.GroupsFromRequest(testChecker, req)
//	c.Assert(err, gc.IsNil)
//	sort.Strings(groups)
//	c.Assert(groups, jc.DeepEquals, []string{"test", "test-group1", "test-group2"})
//}
//
//func (s *authSuite) TestCheckACL(c *gc.C) {
//	testChecker := checkers.OperationChecker("test")
//	s.createIdentity(c, &mongodoc.Identity{
//		Username:   "test",
//		ExternalID: "https://example.com/test",
//		Groups:     []string{"test-group1", "test-group2"},
//	})
//
//	store := s.pool.GetNoLimit()
//	defer s.pool.Put(store)
//
//	// Admin ACL
//	req, err := http.NewRequest("GET", "", nil)
//	c.Assert(err, gc.IsNil)
//	req.SetBasicAuth("test-admin", "open sesame")
//	err = store.CheckACL(testChecker, req, []string{"admin@idm"})
//	c.Assert(err, gc.IsNil)
//
//	// Normal ACL
//	req, err = http.NewRequest("GET", "", nil)
//	c.Assert(err, gc.IsNil)
//	m, err := store.Service.NewMacaroon(bakery.LatestVersion, []checkers.Caveat{
//		checkers.DeclaredCaveat("username", "test"),
//	})
//	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
//	c.Assert(err, gc.IsNil)
//	req.AddCookie(cookie)
//	err = store.CheckACL(testChecker, req, []string{"test-group3", "test-group1"})
//	c.Assert(err, gc.IsNil)
//
//	// No match
//	err = store.CheckACL(testChecker, req, []string{"test-group3", "test-group4"})
//	c.Assert(errgo.Cause(err), gc.Equals, params.ErrForbidden)
//
//	// error getting groups
//	req, err = http.NewRequest("GET", "", nil)
//	c.Assert(err, gc.IsNil)
//	m, err = store.Service.NewMacaroon(bakery.LatestVersion, []checkers.Caveat{
//		checkers.DeclaredCaveat("username", "test2"),
//	})
//	cookie, err = httpbakery.NewCookie(macaroon.Slice{m})
//	c.Assert(err, gc.IsNil)
//	req.AddCookie(cookie)
//	err = store.CheckACL(testChecker, req, []string{"test-group3", "test-group1"})
//	c.Assert(errgo.Cause(err), gc.Equals, params.ErrNotFound)
//}
//
//func (s *authSuite) TestMacaroonRequired(c *gc.C) {
//	testChecker := checkers.OperationChecker("test")
//	store := s.pool.GetNoLimit()
//	defer s.pool.Put(store)
//
//	// Get the groups for the admin user
//	req, err := http.NewRequest("GET", "http://example.com/v1/test", nil)
//	c.Assert(err, gc.IsNil)
//	_, err = store.GroupsFromRequest(testChecker, req)
//	bakeryError, ok := err.(*httpbakery.Error)
//	c.Assert(ok, gc.Equals, true)
//	c.Assert(bakeryError.Code.Error(), gc.Equals, "macaroon discharge required")
//}
