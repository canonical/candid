// Copyright 2014 Canonical Ltd.

package store_test

import (
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

func (s *storeSuite) TestIdentityProvider(c *gc.C) {
	db := s.Session.DB("testing")

	// Add an identity to the identity_providers collection using mgo directly.
	err := db.C("identity_providers").Insert(mongodoc.IdentityProvider{
		Name:     "provider1",
		Protocol: "openid20",
		LoginURL: "https://example.com/login",
	})
	c.Assert(err, gc.IsNil)

	// Set up a new store.
	st, err := store.New(db)
	c.Assert(err, gc.IsNil)

	// Retrieve the identity provider using the store object.
	idp, err := st.IdentityProvider("provider1")
	c.Assert(err, gc.IsNil)
	c.Assert(idp.Name, gc.Equals, "provider1")
	c.Assert(idp.Protocol, gc.Equals, "openid20")
	c.Assert(idp.LoginURL, gc.Equals, "https://example.com/login")
}

func (s *storeSuite) TestIdentityProviderNotFound(c *gc.C) {
	db := s.Session.DB("testing")

	// Set up a new store.
	st, err := store.New(db)
	c.Assert(err, gc.IsNil)

	// Retrieve the identity provider using the store object.
	_, err = st.IdentityProvider("provider1")
	c.Assert(err.Error(), gc.Equals, `cannot get identity provider "provider1": not found`)
}

func (s *storeSuite) TestSetIdentityProvider(c *gc.C) {
	db := s.Session.DB("testing")

	// Set up a new store.
	st, err := store.New(db)
	c.Assert(err, gc.IsNil)

	// Set an identity provider using the store object
	err = st.SetIdentityProvider(&mongodoc.IdentityProvider{
		Name:     "provider1",
		Protocol: "openid20",
		LoginURL: "https://example.com/login",
	})
	c.Assert(err, gc.IsNil)

	// Retrieve the identity provider using the store object.
	idp, err := st.IdentityProvider("provider1")
	c.Assert(err, gc.IsNil)
	c.Assert(idp.Name, gc.Equals, "provider1")
	c.Assert(idp.Protocol, gc.Equals, "openid20")
	c.Assert(idp.LoginURL, gc.Equals, "https://example.com/login")
}

func (s *storeSuite) TestUpdateIdentityProvider(c *gc.C) {
	db := s.Session.DB("testing")

	// Set up a new store.
	st, err := store.New(db)
	c.Assert(err, gc.IsNil)

	// Set an identity provider using the store object
	err = st.SetIdentityProvider(&mongodoc.IdentityProvider{
		Name:     "provider1",
		Protocol: "openid20",
		LoginURL: "https://example.com/login",
	})
	c.Assert(err, gc.IsNil)

	// Update the identity provider using the store object
	err = st.SetIdentityProvider(&mongodoc.IdentityProvider{
		Name:     "provider1",
		Protocol: "openid20",
		LoginURL: "https://example.com/login",
	})
	c.Assert(err, gc.IsNil)

	// Retrieve the identity provider using the store object.
	idp, err := st.IdentityProvider("provider1")
	c.Assert(err, gc.IsNil)
	c.Assert(idp.Name, gc.Equals, "provider1")
	c.Assert(idp.Protocol, gc.Equals, "openid20")
	c.Assert(idp.LoginURL, gc.Equals, "https://example.com/login")
}

func (s *storeSuite) TestListIdentityProviders(c *gc.C) {
	db := s.Session.DB("testing")

	// Set up a new store.
	st, err := store.New(db)
	c.Assert(err, gc.IsNil)

	idps, err := st.IdentityProviderNames()
	c.Assert(err, gc.IsNil)
	c.Assert(idps, gc.HasLen, 0)

	// Set an identity provider using the store object
	err = st.SetIdentityProvider(&mongodoc.IdentityProvider{
		Name:     "provider1",
		Protocol: "openid20",
		LoginURL: "https://example.com/login",
	})
	c.Assert(err, gc.IsNil)

	idps, err = st.IdentityProviderNames()
	c.Assert(err, gc.IsNil)
	c.Assert(idps, gc.HasLen, 1)
	c.Assert(idps[0], gc.Equals, "provider1")

	// Update the identity provider using the store object
	err = st.SetIdentityProvider(&mongodoc.IdentityProvider{
		Name:     "provider2",
		Protocol: "openid20",
		LoginURL: "https://example.com/login",
	})
	c.Assert(err, gc.IsNil)

	idps, err = st.IdentityProviderNames()
	c.Assert(err, gc.IsNil)
	c.Assert(idps, gc.HasLen, 2)
}
