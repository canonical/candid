// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package candidtest

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	qt "github.com/frankban/quicktest"
	aclstore "github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/memsimplekv"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/canonical/candid/candidclient"
	"github.com/canonical/candid/internal/auth"
	"github.com/canonical/candid/internal/identity"
	"github.com/canonical/candid/store"
)

var DefaultTemplate = template.New("")

func init() {
	template.Must(DefaultTemplate.New("authentication-required").Parse(authenticationRequiredTemplate))
	template.Must(DefaultTemplate.New("login").Parse(loginTemplate))
	template.Must(DefaultTemplate.New("login-form").Parse(loginFormTemplate))
}

const (
	// This format is interpretted by SelectInteractiveLogin.
	authenticationRequiredTemplate = "{{range .IDPs}}{{.URL}}\n{{end}}"
	loginTemplate                  = "login successful as user {{.Username}}\n"
	loginFormTemplate              = "{{.Action}}\n{{.Error}}\n"
)

// Server implements a test fixture that contains a candid server.
type Server struct {
	// URL contains the URL of the server.
	URL string

	// Ctx contains a context.Context that has been initialised with
	// the servers.
	Ctx context.Context

	// Key holds the key that the server uses.
	Key *bakery.KeyPair

	// params contains the parameters that were passed to identity.New.
	params            identity.ServerParams
	handler           *identity.Server
	server            *httptest.Server
	adminAgentKey     *bakery.KeyPair
	closeStore        func()
	closeMeetingStore func()
	agentID           int
}

// NewMemServer returns a Server instance
// that uses in-memory storage and serves
// the given API version
func NewMemServer(c *qt.C, versions map[string]identity.NewAPIHandlerFunc) *Server {
	return NewServer(c, NewStore().ServerParams(), versions)
}

// NewServer returns new Server instance. The server parameters must
// contain at least Store, MeetingStore and RootKeyStore. The versions
// argument configures what API versions to serve.
//
// If p.Key is zero then a new key will be generated. If p.PrivateAddr
// is zero then it will default to localhost. If p.Template is zero then
// DefaultTemplate will be used.
func NewServer(c *qt.C, p identity.ServerParams, versions map[string]identity.NewAPIHandlerFunc) *Server {
	return newServer(c, p, versions, "")
}

// NewServerWithSublocation returns a new Server instance. It does the same
// as NewServer, but it allows to specify a sublocation that fakes the
// server as operating from a subpath (e.g. http://serveraddr/sublocation).
func NewServerWithSublocation(c *qt.C, p identity.ServerParams, versions map[string]identity.NewAPIHandlerFunc, sublocation string) *Server {
	return newServer(c, p, versions, sublocation)
}

func newServer(c *qt.C, p identity.ServerParams, versions map[string]identity.NewAPIHandlerFunc, sublocation string) *Server {
	s := new(Server)
	s.params = p
	if s.params.ACLStore == nil {
		s.params.ACLStore = aclstore.NewACLStore(memsimplekv.NewStore())
	}
	s.server = httptest.NewUnstartedServer(nil)
	c.Defer(s.server.Close)
	s.params.Location = "http://" + s.server.Listener.Addr().String() + sublocation
	if s.params.Key == nil {
		var err error
		s.params.Key, err = bakery.GenerateKey()
		c.Assert(err, qt.IsNil)
	}
	s.Key = s.params.Key

	if s.params.PrivateAddr == "" {
		s.params.PrivateAddr = "localhost"
	}
	if s.params.AdminAgentPublicKey == nil {
		var err error
		s.adminAgentKey, err = bakery.GenerateKey()
		c.Assert(err, qt.IsNil)
		s.params.AdminAgentPublicKey = &s.adminAgentKey.Public
	}
	if s.params.Template == nil {
		s.params.Template = DefaultTemplate
	}
	var err error
	s.handler, err = identity.New(s.params, versions)
	c.Assert(err, qt.IsNil)
	c.Defer(s.handler.Close)

	s.server.Config.Handler = http.StripPrefix(sublocation, s.handler)
	s.server.Start()
	s.URL = s.server.URL
	ctx := context.Background()
	ctx, closeStore := s.params.Store.Context(ctx)
	c.Defer(closeStore)

	ctx, closeMeetingStore := s.params.MeetingStore.Context(ctx)
	c.Defer(closeMeetingStore)
	s.Ctx = ctx
	return s
}

// ThirdPartyInfo implements bakery.ThirdPartyLocator.ThirdPartyInfo
// allowing the suite to be used as a bakery.ThirdPartyLocator.
func (s *Server) ThirdPartyInfo(ctx context.Context, loc string) (bakery.ThirdPartyInfo, error) {
	if loc != s.URL {
		return bakery.ThirdPartyInfo{}, bakery.ErrNotFound
	}
	return bakery.ThirdPartyInfo{
		PublicKey: s.params.Key.Public,
		Version:   bakery.LatestVersion,
	}, nil
}

// Client is a convenience method that returns the result of
// calling BakeryClient(i)
func (s *Server) Client(i httpbakery.Interactor) *httpbakery.Client {
	return BakeryClient(i)
}

// BakeryClient creates a new httpbakery.Client which uses the given visitor as
// its WebPageVisitor. If no Visitor is specified then NoVisit will be
// used.
func BakeryClient(i httpbakery.Interactor) *httpbakery.Client {
	cl := &httpbakery.Client{
		Client: httpbakery.NewHTTPClient(),
	}
	if i != nil {
		cl.AddInteractor(i)
	}
	return cl
}

// AdminClient creates a new httpbakery.Client that is configured to log
// in as an admin user.
func (s *Server) AdminClient() *httpbakery.Client {
	client := &httpbakery.Client{
		Client: httpbakery.NewHTTPClient(),
		Key:    s.adminAgentKey,
	}
	agent.SetUpAuth(client, &agent.AuthInfo{
		Key: s.adminAgentKey,
		Agents: []agent.Agent{{
			URL:      s.URL,
			Username: auth.AdminUsername,
		}},
	})
	return client
}

// AdminIdentityClient creates a new candidclient.Client that is configured to log
// in as an admin user.
func (s *Server) AdminIdentityClient(userID bool) *candidclient.Client {
	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.URL,
		Client: &httpbakery.Client{
			Client: httpbakery.NewHTTPClient(),
			Key:    s.adminAgentKey,
		},
		AgentUsername: auth.AdminUsername,
		UseUserID:     userID,
	})
	if err != nil {
		panic(err)
	}
	return client
}

// CreateAgent creates a new agent user in the identity server's store
// with the given name and groups. The agent's username and key are
// returned.
//
// The agent will be owned by admin@candid.
func (s *Server) CreateAgent(c *qt.C, username string, groups ...string) *bakery.KeyPair {
	key, err := bakery.GenerateKey()
	c.Assert(err, qt.IsNil)
	name := strings.TrimSuffix(username, "@candid")
	if name == username {
		c.Fatalf("agent username must end in @candid")
	}
	err = s.params.Store.UpdateIdentity(
		context.Background(),
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("idm", name),
			Username:   username,
			Groups:     groups,
			PublicKeys: []bakery.PublicKey{
				key.Public,
			},
			Owner: auth.AdminProviderID,
		},
		store.Update{
			store.Username:   store.Set,
			store.Groups:     store.Set,
			store.PublicKeys: store.Set,
			store.Owner:      store.Set,
		},
	)
	c.Assert(err, qt.IsNil)
	return key
}

// CreateUser creates a new user in the identity server's store with the
// given name and groups. The user's username is returned.
func (s *Server) CreateUser(c *qt.C, name string, groups ...string) string {
	err := s.params.Store.UpdateIdentity(
		context.Background(),
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("test", name),
			Username:   name,
			Groups:     groups,
		},
		store.Update{
			store.Username: store.Set,
			store.Groups:   store.Set,
		},
	)
	c.Assert(err, qt.IsNil)
	return name
}

// IdentityClient creates a new agent with the given username
// (which must end in @candid) and groups and then creates an
// candidclient.Client
// which authenticates using that agent.
func (s *Server) IdentityClient(c *qt.C, username string, groups ...string) *candidclient.Client {
	key := s.CreateAgent(c, username, groups...)
	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.URL,
		Client: &httpbakery.Client{
			Client: httpbakery.NewHTTPClient(),
			Key:    key,
		},
		AgentUsername: username,
	})
	c.Assert(err, qt.IsNil)
	return client
}

// Do is a convenience function for performing HTTP requests against the
// server. The server's URL will be prepended to the one specified in the
// request and then the request will be performed using
// http.DefaultClient.
func (s *Server) Do(c *qt.C, req *http.Request) *http.Response {
	resp, err := http.DefaultClient.Do(s.reqUrl(c, req))
	c.Assert(err, qt.IsNil)
	return resp
}

// Get is a convenience function for performing HTTP requests against the
// server. The server's URL will be prepended to the one given and then
// the GET will be performed using http.DefaultClient.
func (s *Server) Get(c *qt.C, url string) *http.Response {
	req, err := http.NewRequest("GET", url, nil)
	c.Assert(err, qt.IsNil)
	return s.Do(c, req)
}

// RoundTrip is a convenience function for performing a single HTTP
// requests against the server. The server's URL will be prepended to the
// one specified in the request and then a single request will be
// performed using http.DefaultTransport.
func (s *Server) RoundTrip(c *qt.C, req *http.Request) *http.Response {
	resp, err := http.DefaultTransport.RoundTrip(s.reqUrl(c, req))
	c.Assert(err, qt.IsNil)
	return resp
}

func (s *Server) reqUrl(c *qt.C, req *http.Request) *http.Request {
	u, err := url.Parse(s.URL)
	c.Assert(err, qt.IsNil)
	req.URL = u.ResolveReference(req.URL)
	return req
}

// NoVisit is a httpbakery.Visitor that returns an error without
// attempting a visit.
type NoVisit struct{}

// VisitWebPage implements httpbakery.Visitor.VisitWebPage
func (NoVisit) VisitWebPage(context.Context, *httpbakery.Client, map[string]*url.URL) error {
	return errgo.New("visit not supported")
}
