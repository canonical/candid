// Copyright 2014 Canonical Ltd.

package server

import (
	"net/http"

	"github.com/juju/testing"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/params"
)

type authSuite struct {
	testing.IsolatedMgoSuite
	store *store.Store
}

var _ = gc.Suite(&authSuite{})

func (s *authSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.store, err = store.New(s.Session.DB("idm-test"), lpad.Production)
	c.Assert(err, gc.IsNil)
}

func (s *authSuite) createIdentity(c *gc.C, doc *mongodoc.Identity) (uuid string) {
	err := s.store.UpsertIdentity(doc)
	c.Assert(err, gc.IsNil)
	return doc.UUID
}

func (s *authSuite) TestCheckAdminCredentials(c *gc.C) {
	auth := NewAuthorizer(
		ServerParams{
			AuthUsername: "test-admin",
			AuthPassword: "open sesame",
			Key:          nil,
		},
	)
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
