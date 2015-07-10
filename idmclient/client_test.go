// Copyright 2015 Canonical Ltd.

package idmclient_test

import (
	"net/http/httptest"

	"github.com/juju/testing"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/httpbakery"

	"github.com/CanonicalLtd/blues-identity"
	"github.com/CanonicalLtd/blues-identity/idmclient"
)

type clientSuite struct {
	testing.IsolatedMgoSuite
	service identity.HandlerCloser
	server  *httptest.Server
	key     *bakery.KeyPair
}

var _ = gc.Suite(&clientSuite{})

func (s *clientSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.key, err = bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.service, err = identity.NewServer(
		s.Session.DB("test"),
		identity.ServerParams{
			MaxMgoSessions: 100,
			Key:            s.key,
		},
		identity.V1,
	)
	c.Assert(err, gc.IsNil)
	s.server = httptest.NewServer(s.service)
}

func (s *clientSuite) TearDownTest(c *gc.C) {
	s.server.Close()
	s.service.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

func (s *clientSuite) TestClient(c *gc.C) {
	client := idmclient.New(idmclient.NewParams{
		BaseURL: s.server.URL,
		Client:  httpbakery.NewClient(),
	})
	resp, err := client.PublicKey(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(*resp.PublicKey, gc.Equals, s.key.Public)
}
