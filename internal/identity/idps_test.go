// Copyright 2014 Canonical Ltd.

package identity_test

import (
	"github.com/juju/testing"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
)

type idpsSuite struct {
	testing.IsolatedMgoSuite
	pool *identity.Pool
}

var _ = gc.Suite(&idpsSuite{})

func (s *idpsSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.pool, err = identity.NewPool(s.Session.DB("idps-tests"), identity.ServerParams{})
	c.Assert(err, gc.IsNil)
}

func (s *idpsSuite) TearDownTest(c *gc.C) {
	s.pool.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

func (s *idpsSuite) TestIdentityProvider(c *gc.C) {
	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)
	// Add an identity to the identity_providers collection using mgo directly.
	err := st.DB.IdentityProviders().Insert(mongodoc.IdentityProvider{
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

func (s *idpsSuite) TestIdentityProviderNotFound(c *gc.C) {
	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)

	// Retrieve the identity provider using the store object.
	_, err := st.IdentityProvider("provider1")
	c.Assert(err.Error(), gc.Equals, `cannot get identity provider "provider1": not found`)
}

func (s *idpsSuite) TestSetIdentityProvider(c *gc.C) {
	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)

	// Set an identity provider using the store object
	err := st.SetIdentityProvider(&mongodoc.IdentityProvider{
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

func (s *idpsSuite) TestUpdateIdentityProvider(c *gc.C) {
	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)

	// Set an identity provider using the store object
	err := st.SetIdentityProvider(&mongodoc.IdentityProvider{
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

func (s *idpsSuite) TestListIdentityProviders(c *gc.C) {
	st := s.pool.GetNoLimit()
	defer s.pool.Put(st)

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
