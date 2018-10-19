// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package candidtest

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/candid/internal/auth"
	"github.com/CanonicalLtd/candid/internal/identity"
	"github.com/CanonicalLtd/candid/store"
	"github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/memsimplekv"
)

var DefaultTemplate = template.New("")

func init() {
	template.Must(DefaultTemplate.New("login").Parse(loginTemplate))
}

const loginTemplate = "login successful as user {{.Username}}\n"

// A ServerSuite is a test suite that
type ServerSuite struct {
	// Params is used to configure the server. Any settings must be
	// set before calling SetUpTest. At the least Store, MeetingStore
	// and RootKeyStore must be configured.
	Params identity.ServerParams

	// Versions configures the API versions which will be served by
	// the server. This must be set before calling SetUpTest.
	Versions map[string]identity.NewAPIHandlerFunc

	// The following fields will be available after calling SetUpTest.

	// URL contains the URL of the server.
	URL string

	// Ctx contains a context.Context that has been initialised with
	// the servers.
	Ctx context.Context

	// params contains the final parameters that were passed to
	// identity.New.
	params            identity.ServerParams
	handler           *identity.Server
	server            *httptest.Server
	adminAgentKey     *bakery.KeyPair
	closeStore        func()
	closeMeetingStore func()
	agentID           int
}

// SetUpTest creates a new identity server and serves it. The server is
// configured based on the Params and Versions fields. If the Key
// parameter is not set then a new key will be generated. If the
// PrivateAddr parameter is not set then it will default to localhost. If
// the adminAgentPublicKey is not set then a new key will be generated,
// note that if it is set the AdminClient and AdminIdentityClient can not
// be used. If the Template parameter is not set then DefaultTemplate
// will be used.
func (s *ServerSuite) SetUpTest(c *gc.C) {
	s.params = s.Params
	if s.params.ACLStore == nil {
		s.params.ACLStore = aclstore.NewACLStore(memsimplekv.NewStore())
	}
	s.server = httptest.NewUnstartedServer(nil)
	s.params.Location = "http://" + s.server.Listener.Addr().String()
	if s.params.Key == nil {
		var err error
		s.params.Key, err = bakery.GenerateKey()
		c.Assert(err, gc.Equals, nil)
	}
	if s.params.PrivateAddr == "" {
		s.params.PrivateAddr = "localhost"
	}
	if s.params.AdminAgentPublicKey == nil {
		var err error
		s.adminAgentKey, err = bakery.GenerateKey()
		c.Assert(err, gc.Equals, nil)
		s.params.AdminAgentPublicKey = &s.adminAgentKey.Public
	}
	if s.params.Template == nil {
		s.params.Template = DefaultTemplate
	}
	var err error
	s.handler, err = identity.New(s.params, s.Versions)
	c.Assert(err, gc.Equals, nil)

	s.server.Config.Handler = s.handler
	s.server.Start()
	s.URL = s.server.URL
	s.Ctx, s.closeStore = s.Params.Store.Context(context.Background())
	s.Ctx, s.closeMeetingStore = s.Params.MeetingStore.Context(context.Background())
}

// TearDownTest cleans up the resources created during SetUpTest.
func (s *ServerSuite) TearDownTest(c *gc.C) {
	s.closeMeetingStore()
	s.closeStore()
	s.server.Close()
	s.handler.Close()
}

// ThirdPartyInfo implements bakery.ThirdPartyLocator.THirdPartyInfo
// allowing the suite to be used as a bakery.ThirdPArtyLocator.
func (s *ServerSuite) ThirdPartyInfo(ctx context.Context, loc string) (bakery.ThirdPartyInfo, error) {
	if loc != s.URL {
		return bakery.ThirdPartyInfo{}, bakery.ErrNotFound
	}
	return bakery.ThirdPartyInfo{
		PublicKey: s.params.Key.Public,
		Version:   bakery.LatestVersion,
	}, nil
}

// Client creates a new httpbakery.Client which uses the given visitor as
// its WebPageVisitor. If no Visitor is specified then NoVisit will be
// used.
func (s *ServerSuite) Client(i httpbakery.Interactor) *httpbakery.Client {
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
func (s *ServerSuite) AdminClient() *httpbakery.Client {
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
func (s *ServerSuite) AdminIdentityClient(c *gc.C) *candidclient.Client {
	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.URL,
		Client: &httpbakery.Client{
			Client: httpbakery.NewHTTPClient(),
			Key:    s.adminAgentKey,
		},
		AgentUsername: auth.AdminUsername,
	})
	c.Assert(err, gc.Equals, nil)
	return client
}

// CreateAgent creates a new agent user in the identity server's store
// with the given name and groups. The agent's username and key are
// returned.
//
// The agent will be owned by admin@candid.
func (s *ServerSuite) CreateAgent(c *gc.C, username string, groups ...string) *bakery.KeyPair {
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
	name := strings.TrimSuffix(username, "@candid")
	if name == username {
		c.Fatalf("agent username must end in @candid")
	}
	err = s.Params.Store.UpdateIdentity(
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
	c.Assert(err, gc.Equals, nil)
	return key
}

// CreateUser creates a new user in the identity server's store with the
// given name and groups. The user's username is returned.
func (s *ServerSuite) CreateUser(c *gc.C, name string, groups ...string) string {
	err := s.Params.Store.UpdateIdentity(
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
	c.Assert(err, gc.Equals, nil)
	return name
}

// IdentityClient creates a new agent with the given username
// (which must end in @candid) and groups and then creates an
// candidclient.Client
// which authenticates using that agent.
func (s *ServerSuite) IdentityClient(c *gc.C, username string, groups ...string) *candidclient.Client {
	key := s.CreateAgent(c, username, groups...)
	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.URL,
		Client: &httpbakery.Client{
			Client: httpbakery.NewHTTPClient(),
			Key:    key,
		},
		AgentUsername: username,
	})
	c.Assert(err, gc.Equals, nil)
	return client
}

// Do is a convenience function for performing HTTP requests against the
// server. The server's URL will be prepended to the one specified in the
// request and then the request will be performed using
// http.DefaultClient.
func (s *ServerSuite) Do(c *gc.C, req *http.Request) *http.Response {
	resp, err := http.DefaultClient.Do(s.reqUrl(c, req))
	c.Assert(err, gc.Equals, nil)
	return resp
}

// Get is a convenience function for performing HTTP requests against the
// server. The server's URL will be prepended to the one given and then
// the GET will be performed using http.DefaultClient.
func (s *ServerSuite) Get(c *gc.C, url string) *http.Response {
	req, err := http.NewRequest("GET", url, nil)
	c.Assert(err, gc.Equals, nil)
	return s.Do(c, req)
}

// RoundTrip is a convenience function for performing a single HTTP
// requests against the server. The server's URL will be prepended to the
// one specified in the request and then a single request will be
// performed using http.DefaultTransport.
func (s *ServerSuite) RoundTrip(c *gc.C, req *http.Request) *http.Response {
	resp, err := http.DefaultTransport.RoundTrip(s.reqUrl(c, req))
	c.Assert(err, gc.Equals, nil)
	return resp
}

func (s *ServerSuite) reqUrl(c *gc.C, req *http.Request) *http.Request {
	u, err := url.Parse(s.URL)
	c.Assert(err, gc.Equals, nil)
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
