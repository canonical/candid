// Copyright 2014 Canonical Ltd.

package server

import (
	"net/http"
	"sort"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon.v1"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/params"
)

type authSuite struct {
	testing.IsolatedMgoSuite
	store *store.Store
	svc   *bakery.Service
}

var _ = gc.Suite(&authSuite{})

const identityLocation = "https://identity.test/id"

func (s *authSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.store, err = store.New(s.Session.DB("idm-test"), lpad.Production)
	c.Assert(err, gc.IsNil)
	s.svc, err = bakery.NewService(bakery.NewServiceParams{
		Location: identityLocation,
		Store:    s.store.Macaroons,
		Key:      key,
		Locator: bakery.PublicKeyLocatorMap{
			identityLocation + "/v1/discharger": &key.Public,
		},
	})
	c.Assert(err, gc.IsNil)
}

func (s *authSuite) newAuthorizer(c *gc.C, username, password string) *Authorizer {
	return NewAuthorizer(ServerParams{
		AuthUsername: username,
		AuthPassword: password,
		Location:     identityLocation,
	}, s.store, s.svc)
}

func (s *authSuite) createIdentity(c *gc.C, doc *mongodoc.Identity) (uuid string) {
	err := s.store.UpsertIdentity(doc)
	c.Assert(err, gc.IsNil)
	return doc.UUID
}

func (s *authSuite) TestCheckAdminCredentials(c *gc.C) {
	auth := s.newAuthorizer(c, "test-admin", "open sesame")
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
		obtained := auth.CheckAdminCredentials(&http.Request{
			Header: test.header,
		})
		if test.expectErrorMessage == "" {
			c.Assert(obtained, gc.Equals, nil)
		} else {
			c.Assert(obtained.Error(), gc.Equals, test.expectErrorMessage)
		}
	}
}

func (s *authSuite) TestUserHasPublicKey(c *gc.C) {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.createIdentity(c, &mongodoc.Identity{
		Username: "test",
		Owner:    "admin",
		PublicKeys: []mongodoc.PublicKey{
			{Key: key.Public.Key[:]},
		},
	})
	cav := UserHasPublicKeyCaveat(params.Username("test"), &key.Public)
	c.Assert(cav.Location, gc.Equals, "")
	c.Assert(cav.Condition, gc.Matches, "user-has-public-key test .*")

	var identity *mongodoc.Identity
	check := UserHasPublicKeyChecker{
		Store:    s.store,
		Identity: &identity,
	}
	c.Assert(check.Condition(), gc.Equals, "user-has-public-key")
	cond, arg, err := checkers.ParseCaveat(cav.Condition)
	c.Assert(err, gc.IsNil)
	err = check.Check(cond, arg)
	c.Assert(err, gc.IsNil)
	c.Assert(identity.Username, gc.Equals, "test")

	// Unknown username
	arg = "test2 " + key.Public.String()
	err = check.Check(cond, arg)
	c.Assert(err, gc.ErrorMatches, "public key not valid for user")

	// Incorrect public key
	arg = "test " + "A" + key.Public.String()[1:]
	err = check.Check(cond, arg)
	c.Assert(err, gc.ErrorMatches, "public key not valid for user")

	// Invalid argument
	arg = "test"
	err = check.Check(cond, arg)
	c.Assert(err, gc.ErrorMatches, "caveat badly formatted")

	// Invalid username
	arg = "= " + key.Public.String()
	err = check.Check(cond, arg)
	c.Assert(err, gc.ErrorMatches, `illegal username "="`)

	// Invalid public key
	arg = "test " + key.Public.String()[1:]
	err = check.Check(cond, arg)
	c.Assert(err, gc.ErrorMatches, `invalid public key ".*": .*`)
}

func (s *authSuite) TestGroupsFromRequest(c *gc.C) {
	auth := s.newAuthorizer(c, "test-admin", "open sesame")

	// Get the groups for the admin user
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, gc.IsNil)
	req.SetBasicAuth("test-admin", "open sesame")
	groups, err := auth.groupsFromRequest("test", req)
	c.Assert(err, gc.IsNil)
	c.Assert(len(groups), gc.Equals, 1)
	c.Assert(groups[0], gc.Equals, "admin@idm")

	// Incorrect admin credentials
	req, err = http.NewRequest("GET", "", nil)
	c.Assert(err, gc.IsNil)
	req.SetBasicAuth("test-admin", "open simsim")
	groups, err = auth.groupsFromRequest("test", req)
	c.Assert(len(groups), gc.Equals, 0)
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrUnauthorized)

	// Request with no credentials (discharge required)
	req, err = http.NewRequest("GET", "", nil)
	c.Assert(err, gc.IsNil)
	groups, err = auth.groupsFromRequest("test", req)
	c.Assert(len(groups), gc.Equals, 0)
	herr, ok := err.(*httpbakery.Error)
	c.Assert(ok, gc.Equals, true, gc.Commentf("unexpected error %s", err))
	c.Assert(herr.Code, gc.Equals, httpbakery.ErrDischargeRequired)
	c.Assert(herr.Info.MacaroonPath, gc.Equals, "/id")
	c.Assert(herr.Info.Macaroon, gc.Not(gc.IsNil))
	var foundThirdParty bool
	for _, cav := range herr.Info.Macaroon.Caveats() {
		if cav.Location == "" {
			continue
		}
		c.Assert(cav.Location, gc.Equals, identityLocation+"/v1/discharger")
		foundThirdParty = true
	}
	c.Assert(foundThirdParty, gc.Equals, true)

	// Non-existent identity
	m, err := s.svc.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", "test2"),
	})
	c.Assert(err, gc.IsNil)
	req, err = http.NewRequest("GET", "", nil)
	c.Assert(err, gc.IsNil)
	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
	c.Assert(err, gc.IsNil)
	req.AddCookie(cookie)
	groups, err = auth.groupsFromRequest("test", req)
	c.Assert(len(groups), gc.Equals, 0)
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrNotFound)

	// good identity
	s.createIdentity(c, &mongodoc.Identity{
		Username:   "test",
		ExternalID: "https://example.com/test",
		Groups:     []string{"test-group1", "test-group2"},
	})
	m, err = s.svc.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", "test"),
	})
	req, err = http.NewRequest("GET", "", nil)
	c.Assert(err, gc.IsNil)
	cookie, err = httpbakery.NewCookie(macaroon.Slice{m})
	c.Assert(err, gc.IsNil)
	req.AddCookie(cookie)
	groups, err = auth.groupsFromRequest("test", req)
	c.Assert(err, gc.IsNil)
	sort.Strings(groups)
	c.Assert(groups, jc.DeepEquals, []string{"test", "test-group1", "test-group2"})
}

func (s *authSuite) TestCheckACL(c *gc.C) {
	s.createIdentity(c, &mongodoc.Identity{
		Username:   "test",
		ExternalID: "https://example.com/test",
		Groups:     []string{"test-group1", "test-group2"},
	})

	auth := s.newAuthorizer(c, "test-admin", "open sesame")

	// Admin ACL
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, gc.IsNil)
	req.SetBasicAuth("test-admin", "open sesame")
	err = auth.CheckACL("test", req, []string{"admin@idm"})
	c.Assert(err, gc.IsNil)

	// Normal ACL
	req, err = http.NewRequest("GET", "", nil)
	c.Assert(err, gc.IsNil)
	m, err := s.svc.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", "test"),
	})
	cookie, err := httpbakery.NewCookie(macaroon.Slice{m})
	c.Assert(err, gc.IsNil)
	req.AddCookie(cookie)
	err = auth.CheckACL("test", req, []string{"test-group3", "test-group1"})
	c.Assert(err, gc.IsNil)

	// No match
	err = auth.CheckACL("test", req, []string{"test-group3", "test-group4"})
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrForbidden)

	// error getting groups
	req, err = http.NewRequest("GET", "", nil)
	c.Assert(err, gc.IsNil)
	m, err = s.svc.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("username", "test2"),
	})
	cookie, err = httpbakery.NewCookie(macaroon.Slice{m})
	c.Assert(err, gc.IsNil)
	req.AddCookie(cookie)
	err = auth.CheckACL("test", req, []string{"test-group3", "test-group1"})
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrNotFound)
}
