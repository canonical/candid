// Copyright 2015 Canonical Ltd.

package idmclient_test

import (
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/juju/testing"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon-bakery.v1/httpbakery/agent"

	"github.com/CanonicalLtd/blues-identity"
	"github.com/CanonicalLtd/blues-identity/idmclient"
	internalIdentity "github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/params"
)

type clientSuite struct {
	testing.IsolatedMgoSuite
	service identity.HandlerCloser
	server  *httptest.Server
	key     *bakery.KeyPair
	users   map[string]*bakery.KeyPair
}

var _ = gc.Suite(&clientSuite{})

func (s *clientSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.key, err = bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.users = make(map[string]*bakery.KeyPair)
	s.server = httptest.NewUnstartedServer(nil)
	s.service, err = identity.NewServer(
		s.Session.DB("test"),
		identity.ServerParams{
			MaxMgoSessions: 100,
			Key:            s.key,
			AuthUsername:   "admin",
			Location:       "http://" + s.server.Listener.Addr().String(),
			AuthPassword:   "password",
		},
		identity.V1,
	)
	c.Assert(err, gc.IsNil)
	s.server.Config.Handler = s.service
	s.server.Start()
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

func (s *clientSuite) TestClientWithBasicAuth(c *gc.C) {
	s.addUser(c, "alice", internalIdentity.GroupListGroup)
	client := s.userClient(c, "alice")
	groups, err := client.UserGroups(&params.UserGroupsRequest{
		Username: "bob",
	})
	c.Assert(groups, gc.HasLen, 0)
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrNotFound)
}

func (s *clientSuite) TestPermChecker(c *gc.C) {
	s.addUser(c, "alice", internalIdentity.GroupListGroup)
	client := s.userClient(c, "alice")

	pc := idmclient.NewPermChecker(client, time.Hour)

	// No permissions always yields false.
	ok, err := pc.Allow("bob", nil)
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, false)

	// If the user isn't found, we return a (false, nil)
	ok, err = pc.Allow("bob", []string{"beatles"})
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, false)

	// If the perms allow everyone, it's ok
	ok, err = pc.Allow("bob", []string{"noone", "everyone"})
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, true)

	// If the perms allow the user itself, it's ok
	ok, err = pc.Allow("bob", []string{"noone", "bob"})
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, true)

	err = s.adminClient().SetUser(&params.SetUserRequest{
		Username: "bob",
		User: params.User{
			ExternalID: "externalid",
			IDPGroups:  []string{"beatles"},
		},
	})
	c.Assert(err, gc.IsNil)

	// The group details are currently cached by the client,
	// so the original request will still fail.
	ok, err = pc.Allow("bob", []string{"beatles"})
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, false)

	// Clearing the cache allows it to succeed.
	pc.CacheEvictAll()
	ok, err = pc.Allow("bob", []string{"beatles"})
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, true)
}

// addUser creates a new user with the given user name
// that is in the given groups.
func (s *clientSuite) addUser(c *gc.C, name string, groups ...string) {
	kp, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	client := s.adminClient()
	err = client.SetUser(&params.SetUserRequest{
		Username: params.Username(name),
		User: params.User{
			IDPGroups:  groups,
			ExternalID: name + "@external",
			PublicKeys: []*bakery.PublicKey{&kp.Public},
		},
	})
	c.Assert(err, gc.IsNil)
	c.Logf("added user %s; public key %s", name, kp.Public)
	s.users[name] = kp
}

// userClient returns an idm client that acts as the given
// user, which must have been previously added with clientSuite.newUser.
func (s *clientSuite) userClient(c *gc.C, name string) *idmclient.Client {
	key, ok := s.users[name]
	c.Assert(ok, gc.Equals, true)
	bclient := httpbakery.NewClient()
	bclient.Key = key
	u, err := url.Parse(s.server.URL)
	c.Assert(err, gc.IsNil)
	agent.SetUpAuth(bclient, u, name)
	return idmclient.New(idmclient.NewParams{
		BaseURL: s.server.URL,
		Client:  bclient,
	})
}

// adminClient reeturns an idm client that acts as the
// administrator.
func (s *clientSuite) adminClient() *idmclient.Client {
	return idmclient.New(idmclient.NewParams{
		BaseURL:      s.server.URL,
		Client:       httpbakery.NewClient(),
		AuthUsername: "admin",
		AuthPassword: "password",
	})
}
