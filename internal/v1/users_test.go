// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package v1_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"gopkg.in/CanonicalLtd/candidclient.v1"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/static"
	"github.com/canonical/candid/internal/auth"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/internal/discharger"
	"github.com/canonical/candid/internal/identity"
	"github.com/canonical/candid/internal/v1"
	"github.com/canonical/candid/store"
)

func TestUsersAPI(t *testing.T) {
	qtsuite.Run(qt.New(t), &usersSuite{})
}

type usersSuite struct {
	store       *candidtest.Store
	srv         *candidtest.Server
	adminClient *candidclient.Client
	interactor  httpbakery.WebBrowserInteractor
}

func (s *usersSuite) Init(c *qt.C) {
	s.store = candidtest.NewStore()
	sp := s.store.ServerParams()
	// Ensure that there's an identity provider for the test identities
	// we add so that group resolution on test identities works correctly.
	sp.IdentityProviders = []idp.IdentityProvider{
		static.NewIdentityProvider(static.Params{
			Name: "test",
			Users: map[string]static.UserInfo{
				"bob": {
					Password: "bobpassword",
					Groups:   []string{"g1", "g2", "testgroup"},
				},
			},
		}),
	}
	s.srv = candidtest.NewServer(c, sp, map[string]identity.NewAPIHandlerFunc{
		"discharger": discharger.NewAPIHandler,
		"v1":         v1.NewAPIHandler,
	})
	s.adminClient = s.srv.AdminIdentityClient()
	s.interactor = httpbakery.WebBrowserInteractor{
		OpenWebBrowser: candidtest.PasswordLogin(c, "bob", "bobpassword"),
	}
}

func (s *usersSuite) TestRoundTripUser(c *qt.C) {
	user := params.User{
		Username:   "jbloggs",
		ExternalID: "test:http://example.com/jbloggs",
		FullName:   "Joe Bloggs",
		Email:      "jbloggs@example.com",
		IDPGroups: []string{
			"test",
		},
	}
	s.addUser(c, user)

	resp, err := s.adminClient.User(s.srv.Ctx, &params.UserRequest{
		Username: user.Username,
	})
	c.Assert(err, qt.Equals, nil)
	s.assertUser(c, *resp, user)
}

func (s *usersSuite) TestUsernameContainingUnderscore(c *qt.C) {
	user := params.User{
		Username:   "jbloggs_TEST",
		ExternalID: "test:http://example.com/jbloggs",
		FullName:   "Joe Bloggs",
		Email:      "jbloggs@example.com",
		IDPGroups: []string{
			"test",
		},
	}
	s.addUser(c, user)

	resp, err := s.adminClient.User(s.srv.Ctx, &params.UserRequest{
		Username: user.Username,
	})
	c.Assert(err, qt.Equals, nil)
	s.assertUser(c, *resp, user)
}

var userErrorTests = []struct {
	about       string
	username    params.Username
	expectError string
}{{
	about:       "not found",
	username:    "not-there",
	expectError: `Get .*/v1/u/not-there: user not-there not found`,
}, {
	about:       "bad username",
	username:    "verylongname_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	expectError: `Get .*/v1/u/verylongname_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: cannot unmarshal parameters: cannot unmarshal into field Username: username longer than 256 characters`,
}}

func (s *usersSuite) TestUserErrors(c *qt.C) {
	for _, test := range userErrorTests {
		c.Run(test.about, func(c *qt.C) {
			_, err := s.adminClient.User(s.srv.Ctx, &params.UserRequest{
				Username: test.username,
			})
			c.Assert(err, qt.ErrorMatches, test.expectError)
		})
	}
}

var (
	privKey1 = bakery.MustGenerateKey()
	pk1      = privKey1.Public
	privKey2 = bakery.MustGenerateKey()
	pk2      = privKey2.Public
)

func (s *usersSuite) TestCreateAgent(c *qt.C) {
	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.srv.URL,
		Client:  s.srv.Client(s.interactor),
	})
	c.Assert(err, qt.Equals, nil)
	resp, err := client.CreateAgent(s.srv.Ctx, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			FullName:   "my agent",
			PublicKeys: []*bakery.PublicKey{&pk1},
		},
	})
	c.Assert(err, qt.Equals, nil)
	if !strings.HasPrefix(string(resp.Username), "a-") {
		c.Errorf("unexpected agent username %q", resp.Username)
	}
	agentClient, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.srv.URL,
		Client: &httpbakery.Client{
			Client: httpbakery.NewHTTPClient(),
			Key:    privKey1,
		},
		AgentUsername: string(resp.Username),
	})
	c.Assert(err, qt.Equals, nil)

	whoAmIResp, err := agentClient.WhoAmI(s.srv.Ctx, nil)
	c.Assert(err, qt.Equals, nil)
	c.Assert(whoAmIResp.User, qt.Equals, string(resp.Username))

	groups, err := agentClient.UserGroups(s.srv.Ctx, &params.UserGroupsRequest{
		Username: resp.Username,
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.HasLen, 0)
}

func (s *usersSuite) TestCreateAgentAsAgent(c *qt.C) {
	client := s.srv.IdentityClient(c, "testagent@candid", "testgroup")
	_, err := client.CreateAgent(s.srv.Ctx, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			FullName:   "my agent",
			PublicKeys: []*bakery.PublicKey{&pk1},
		},
	})
	c.Assert(err, qt.ErrorMatches, `Post.*: cannot create an agent using an agent account`)
}

func (s *usersSuite) TestCreateAgentWithGroups(c *qt.C) {
	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.srv.URL,
		Client:  s.srv.Client(s.interactor),
	})
	c.Assert(err, qt.Equals, nil)

	// We can't create agents in groups that aren't in the owner's
	// group list.
	resp, err := client.CreateAgent(s.srv.Ctx, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			PublicKeys: []*bakery.PublicKey{&pk1},
			Groups:     []string{"g1", "other", "g2"},
		},
	})
	c.Assert(err, qt.ErrorMatches, `Post .*: cannot add agent to groups that you are not a member of`)

	s.setUserGroups(c, "bob", "g3")

	// We can create agents in groups that are a subset of the
	// owner's groups.
	resp, err = client.CreateAgent(s.srv.Ctx, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			PublicKeys: []*bakery.PublicKey{&pk1},
			Groups:     []string{"g1", "g3"},
		},
	})
	c.Assert(err, qt.Equals, nil)

	// If the owner is removed from a group, the agent won't be
	// in that group any more.
	s.setUserGroups(c, "bob")

	groups, err := s.adminClient.UserGroups(s.srv.Ctx, &params.UserGroupsRequest{
		Username: resp.Username,
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"g1"})

	// If the owner is added back to the group, the agent
	// gets added back too.
	s.setUserGroups(c, "bob", "g3", "g4")

	groups, err = s.adminClient.UserGroups(s.srv.Ctx, &params.UserGroupsRequest{
		Username: resp.Username,
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"g1", "g3"})
}

func (s *usersSuite) setUserGroups(c *qt.C, username string, groups ...string) {
	err := s.store.Store.UpdateIdentity(s.srv.Ctx, &store.Identity{
		Username: username,
		Groups:   groups,
	}, store.Update{
		store.Groups: store.Set,
	})
	c.Assert(err, qt.Equals, nil)
}

func (s *usersSuite) TestCreateParentAgent(c *qt.C) {
	resp, err := s.adminClient.CreateAgent(s.srv.Ctx, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			FullName:   "my agent",
			PublicKeys: []*bakery.PublicKey{&pk1},
			Groups:     []string{"g1", "g2"},
			Parent:     true,
		},
	})
	c.Assert(err, qt.Equals, nil)
	if !strings.HasPrefix(string(resp.Username), "a-") {
		c.Errorf("unexpected agent username %q", resp.Username)
	}
	systemUserClient, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.srv.URL,
		Client: &httpbakery.Client{
			Client: httpbakery.NewHTTPClient(),
			Key:    privKey1,
		},
		AgentUsername: string(resp.Username),
	})
	c.Assert(err, qt.Equals, nil)

	whoAmIResp, err := systemUserClient.WhoAmI(s.srv.Ctx, nil)
	c.Assert(err, qt.Equals, nil)
	c.Assert(whoAmIResp.User, qt.Equals, string(resp.Username))

	groups, err := systemUserClient.UserGroups(s.srv.Ctx, &params.UserGroupsRequest{
		Username: resp.Username,
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"g1", "g2"})
}

func (s *usersSuite) TestCreateParentAgentUnauthorized(c *qt.C) {
	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.srv.URL,
		Client:  s.srv.Client(s.interactor),
	})
	c.Assert(err, qt.Equals, nil)

	_, err = client.CreateAgent(s.srv.Ctx, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			FullName:   "my agent",
			PublicKeys: []*bakery.PublicKey{&pk1},
			Groups:     []string{"g1", "g2"},
			Parent:     true,
		},
	})
	c.Assert(err, qt.ErrorMatches, `Post http://.*/v1/u: permission denied`)
}

func (s *usersSuite) TestCreateParentAgentNotInGroups(c *qt.C) {
	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.srv.URL,
		Client:  s.srv.Client(s.interactor),
	})
	c.Assert(err, qt.Equals, nil)

	err = s.store.ACLStore.Add(s.srv.Ctx, "write-user", []string{"bob"})
	c.Assert(err, qt.Equals, nil)

	_, err = client.CreateAgent(s.srv.Ctx, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			FullName:   "my agent",
			PublicKeys: []*bakery.PublicKey{&pk1},
			Groups:     []string{"g1", "g3"},
			Parent:     true,
		},
	})
	c.Assert(err, qt.ErrorMatches, `Post http://.*/v1/u: cannot add agent to groups that you are not a member of`)
}

func (s *usersSuite) TestCreateAgentAsParentAgent(c *qt.C) {
	resp, err := s.adminClient.CreateAgent(s.srv.Ctx, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			FullName:   "my agent",
			PublicKeys: []*bakery.PublicKey{&pk1},
			Parent:     true,
		},
	})
	c.Assert(err, qt.Equals, nil)
	if !strings.HasPrefix(string(resp.Username), "a-") {
		c.Errorf("unexpected agent username %q", resp.Username)
	}
	systemUserClient, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.srv.URL,
		Client: &httpbakery.Client{
			Client: httpbakery.NewHTTPClient(),
			Key:    privKey1,
		},
		AgentUsername: string(resp.Username),
	})
	c.Assert(err, qt.Equals, nil)

	resp, err = systemUserClient.CreateAgent(s.srv.Ctx, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			FullName:   "my agent 2",
			PublicKeys: []*bakery.PublicKey{&pk1},
		},
	})
	c.Assert(err, qt.Equals, nil)

	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.srv.URL,
		Client: &httpbakery.Client{
			Client: httpbakery.NewHTTPClient(),
			Key:    privKey1,
		},
		AgentUsername: string(resp.Username),
	})
	c.Assert(err, qt.Equals, nil)
	_, err = client.CreateAgent(s.srv.Ctx, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			FullName:   "my agent",
			PublicKeys: []*bakery.PublicKey{&pk1},
		},
	})
	c.Assert(err, qt.ErrorMatches, `Post.*: cannot create an agent using an agent account`)
}

func (s *usersSuite) clearIdentities(c *qt.C) {
	store, ok := s.store.Store.(interface {
		RemoveAll()
	})
	if !ok {
		c.Fatalf("store type %T does not implement RemoveAll", s.store.Store)
	}
	store.RemoveAll()
}

var queryUserTests = []struct {
	about              string
	externalID         string
	email              string
	lastLoginSince     time.Time
	lastDIschargeSince time.Time
	expect             []string
}{{
	about:      "query existing user",
	externalID: "test:http://example.com/jbloggs2",
	expect:     []string{"jbloggs2"},
}, {
	about:      "query non-existing user",
	externalID: "test:http://example.com/jbloggs",
	expect:     []string{},
}, {
	about:  "no query parameter",
	expect: []string{auth.AdminUsername, "jbloggs2"},
}, {
	about:  "query email",
	email:  "jbloggs2@example.com",
	expect: []string{"jbloggs2"},
}, {
	about:  "query email not found",
	email:  "not-there@example.com",
	expect: []string{},
}, {
	about:          "last login in range",
	externalID:     "test:http://example.com/jbloggs2",
	lastLoginSince: time.Now().AddDate(0, 0, -30),
	expect:         []string{"jbloggs2"},
}, {
	about:          "last login too soon",
	externalID:     "test:http://example.com/jbloggs2",
	lastLoginSince: time.Now().AddDate(0, 0, -28),
	expect:         []string{},
}, {
	about:              "last discharge in range",
	externalID:         "test:http://example.com/jbloggs2",
	lastDIschargeSince: time.Now().AddDate(0, 0, -15),
	expect:             []string{"jbloggs2"},
}, {
	about:              "last discharge too soon",
	externalID:         "test:http://example.com/jbloggs2",
	lastDIschargeSince: time.Now().AddDate(0, 0, -13),
	expect:             []string{},
}, {
	about:              "combined login and discharge (found)",
	externalID:         "test:http://example.com/jbloggs2",
	lastLoginSince:     time.Now().AddDate(0, 0, -30),
	lastDIschargeSince: time.Now().AddDate(0, 0, -15),
	expect:             []string{"jbloggs2"},
}, {
	about:              "combined login and discharge (not found)",
	externalID:         "test:http://example.com/jbloggs2",
	lastLoginSince:     time.Now().AddDate(0, 0, -30),
	lastDIschargeSince: time.Now().AddDate(0, 0, -13),
	expect:             []string{},
}}

func (s *usersSuite) TestQueryUsers(c *qt.C) {
	err := s.store.Store.UpdateIdentity(
		s.srv.Ctx,
		&store.Identity{
			Username:      "jbloggs2",
			ProviderID:    "test:http://example.com/jbloggs2",
			Name:          "Joe Bloggs II",
			Email:         "jbloggs2@example.com",
			LastLogin:     time.Now().AddDate(0, 0, -29),
			LastDischarge: time.Now().AddDate(0, 0, -14),
			Groups: []string{
				"test",
			},
		},
		store.Update{
			store.Username:      store.Set,
			store.Name:          store.Set,
			store.Groups:        store.Set,
			store.Email:         store.Set,
			store.LastLogin:     store.Set,
			store.LastDischarge: store.Set,
		},
	)
	c.Assert(err, qt.Equals, nil)
	for _, test := range queryUserTests {
		c.Run(test.about, func(c *qt.C) {
			req := params.QueryUsersRequest{
				ExternalID: test.externalID,
				Email:      test.email,
			}
			if !test.lastLoginSince.IsZero() {
				req.LastLoginSince = test.lastLoginSince.Format(time.RFC3339Nano)
			}
			if !test.lastDIschargeSince.IsZero() {
				req.LastDischargeSince = test.lastDIschargeSince.Format(time.RFC3339Nano)
			}
			users, err := s.adminClient.QueryUsers(s.srv.Ctx, &req)
			c.Assert(err, qt.Equals, nil)
			c.Assert(users, qt.DeepEquals, test.expect)
		})
	}
}

func (s *usersSuite) TestQueryUsersBadLastLogin(c *qt.C) {
	_, err := s.adminClient.QueryUsers(s.srv.Ctx, &params.QueryUsersRequest{
		LastLoginSince: "yesterday",
	})
	c.Assert(err, qt.ErrorMatches, `Get http://.*/v1/u?.*last-login-since=yesterday.*: cannot unmarshal last-login-since: parsing time "yesterday" as "2006-01-02T15:04:05Z07:00": cannot parse "yesterday" as "2006"`)
}

func (s *usersSuite) TestQueryUsersBadLastDischarge(c *qt.C) {
	_, err := s.adminClient.QueryUsers(s.srv.Ctx, &params.QueryUsersRequest{
		LastDischargeSince: "yesterday",
	})
	c.Assert(err, qt.ErrorMatches, `Get http://.*/v1/u?.*last-discharge-since=yesterday.*: cannot unmarshal last-discharge-since: parsing time "yesterday" as "2006-01-02T15:04:05Z07:00": cannot parse "yesterday" as "2006"`)
}

func (s *usersSuite) TestQueryUsersUnauthorized(c *qt.C) {
	client := s.srv.IdentityClient(c, "a-bob@candid", "bob")
	_, err := client.QueryUsers(s.srv.Ctx, &params.QueryUsersRequest{})
	c.Assert(err, qt.ErrorMatches, `Get http://.*/v1/u?.*: permission denied`)
}

func (s *usersSuite) TestQueryAgentUsers(c *qt.C) {
	err := s.store.Store.UpdateIdentity(
		s.srv.Ctx,
		&store.Identity{
			Username:      "jbloggs2",
			ProviderID:    "test:http://example.com/jbloggs2",
			Name:          "Joe Bloggs II",
			Email:         "jbloggs2@example.com",
			LastLogin:     time.Now().AddDate(0, 0, -29),
			LastDischarge: time.Now().AddDate(0, 0, -14),
			Groups: []string{
				"test",
			},
		},
		store.Update{
			store.Username:      store.Set,
			store.Name:          store.Set,
			store.Groups:        store.Set,
			store.Email:         store.Set,
			store.LastLogin:     store.Set,
			store.LastDischarge: store.Set,
		},
	)
	c.Assert(err, qt.Equals, nil)
	err = s.store.Store.UpdateIdentity(
		s.srv.Ctx,
		&store.Identity{
			Username:   "a-agent@candid",
			ProviderID: "idm:a-agent",
			Owner:      "test:http://example.com/jbloggs2",
		},
		store.Update{
			store.Username: store.Set,
			store.Owner:    store.Set,
		},
	)
	c.Assert(err, qt.Equals, nil)
	client := s.srv.IdentityClient(c, "a-jbloggs2@candid", "jbloggs2")
	users, err := client.QueryUsers(s.srv.Ctx, &params.QueryUsersRequest{
		Owner: "jbloggs2",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(users, qt.DeepEquals, []string{"a-agent@candid"})
}

func (s *usersSuite) TestQueryAgentUsersOwnerNotFound(c *qt.C) {
	client := s.srv.IdentityClient(c, "a-jbloggs2@candid", "test")
	users, err := client.QueryUsers(s.srv.Ctx, &params.QueryUsersRequest{
		Owner: "test",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(users, qt.DeepEquals, []string{})
}

func (s *usersSuite) TestSSHKeys(c *qt.C) {
	s.addUser(c, params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
		Email:      "jbloggs@example.com",
		FullName:   "Joe Bloggs",
		IDPGroups: []string{
			"test",
		},
	})

	// Check there is no ssh key for the user.
	sshKeys, err := s.adminClient.GetSSHKeys(s.srv.Ctx, &params.SSHKeysRequest{
		Username: "jbloggs",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(sshKeys.SSHKeys, qt.DeepEquals, []string(nil))

	// Add ssh keys to the user.
	err = s.adminClient.PutSSHKeys(s.srv.Ctx, &params.PutSSHKeysRequest{
		Username: "jbloggs",
		Body: params.PutSSHKeysBody{
			SSHKeys: []string{"36ASDER56", "22ERT56DG", "56ASDFASDF32"},
			Add:     false,
		},
	})
	c.Assert(err, qt.Equals, nil)

	// Check it is present.
	sshKeys, err = s.adminClient.GetSSHKeys(s.srv.Ctx, &params.SSHKeysRequest{
		Username: "jbloggs",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(sshKeys.SSHKeys, qt.DeepEquals, []string{
		"36ASDER56",
		"22ERT56DG",
		"56ASDFASDF32",
	})

	// Remove some ssh keys.
	err = s.adminClient.DeleteSSHKeys(s.srv.Ctx, &params.DeleteSSHKeysRequest{
		Username: "jbloggs",
		Body: params.DeleteSSHKeysBody{
			SSHKeys: []string{"22ERT56DG", "56ASDFASDF32"},
		},
	})
	c.Assert(err, qt.Equals, nil)

	// Check we only get one.
	sshKeys, err = s.adminClient.GetSSHKeys(s.srv.Ctx, &params.SSHKeysRequest{
		Username: "jbloggs",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(sshKeys.SSHKeys, qt.DeepEquals, []string{
		"36ASDER56",
	})

	// Delete an unknown ssh key just do nothing silently.
	err = s.adminClient.DeleteSSHKeys(s.srv.Ctx, &params.DeleteSSHKeysRequest{
		Username: "jbloggs",
		Body: params.DeleteSSHKeysBody{
			SSHKeys: []string{"22ERT56DG"},
		},
	})
	c.Assert(err, qt.Equals, nil)

	// Check we only get one.
	sshKeys, err = s.adminClient.GetSSHKeys(s.srv.Ctx, &params.SSHKeysRequest{
		Username: "jbloggs",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(sshKeys.SSHKeys, qt.DeepEquals, []string{
		"36ASDER56",
	})

	// Append one ssh key.
	err = s.adminClient.PutSSHKeys(s.srv.Ctx, &params.PutSSHKeysRequest{
		Username: "jbloggs",
		Body: params.PutSSHKeysBody{
			SSHKeys: []string{"90SDFGS45"},
			Add:     true,
		},
	})
	c.Assert(err, qt.Equals, nil)

	// Check we get two.
	sshKeys, err = s.adminClient.GetSSHKeys(s.srv.Ctx, &params.SSHKeysRequest{
		Username: "jbloggs",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(sshKeys.SSHKeys, qt.DeepEquals, []string{
		"36ASDER56",
		"90SDFGS45",
	})
}

func (s *usersSuite) TestVerifyUserToken(c *qt.C) {
	s.addUser(c, params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
		Email:      "jbloggs@example.com",
		FullName:   "Joe Bloggs",
		IDPGroups: []string{
			"test",
		},
	})

	m, err := s.adminClient.UserToken(s.srv.Ctx, &params.UserTokenRequest{
		Username: "jbloggs",
	})
	c.Assert(err, qt.Equals, nil)

	declared, err := s.adminClient.VerifyToken(s.srv.Ctx, &params.VerifyTokenRequest{
		Macaroons: macaroon.Slice{m.M()},
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(declared, qt.DeepEquals, map[string]string{
		"username": "jbloggs",
	})

	badm, err := macaroon.New([]byte{}, []byte("no such macaroon"), "loc", macaroon.LatestVersion)
	c.Assert(err, qt.Equals, nil)
	_, err = s.adminClient.VerifyToken(s.srv.Ctx, &params.VerifyTokenRequest{
		Macaroons: macaroon.Slice{badm},
	})
	c.Assert(err, qt.ErrorMatches, `Post .*/v1/verify: verification failure: macaroon discharge required: authentication required`)
}

func (s *usersSuite) TestUserTokenNotFound(c *qt.C) {
	_, err := s.adminClient.UserToken(s.srv.Ctx, &params.UserTokenRequest{
		Username: "not-there",
	})
	c.Assert(err, qt.ErrorMatches, `Get .*/v1/u/not-there/macaroon: user not-there not found`)
}

func (s *usersSuite) TestDischargeToken(c *qt.C) {
	s.addUser(c, params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
		Email:      "jbloggs@example.com",
		FullName:   "Joe Bloggs",
		IDPGroups: []string{
			"test",
		},
	})

	client := &httprequest.Client{
		BaseURL: s.srv.URL,
		Doer:    s.srv.AdminClient(),
	}
	var resp params.DischargeTokenForUserResponse
	err := client.Get(s.srv.Ctx, "/v1/discharge-token-for-user?username=jbloggs", &resp)
	c.Assert(err, qt.Equals, nil)

	declared, err := s.adminClient.VerifyToken(s.srv.Ctx, &params.VerifyTokenRequest{
		Macaroons: macaroon.Slice{resp.DischargeToken.M()},
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(declared, qt.DeepEquals, map[string]string{
		"username": "jbloggs",
	})
}

var userGroupTests = []struct {
	about        string
	username     params.Username
	expectGroups []string
	expectError  string
}{{
	about:        "no groups",
	username:     "jbloggs",
	expectGroups: []string{},
}, {
	about:        "groups",
	username:     "jbloggs2",
	expectGroups: []string{"test1", "test2"},
}, {
	about:       "no such user",
	username:    "not-there",
	expectError: `Get .*/v1/u/not-there/groups: user not-there not found`,
}}

func (s *usersSuite) TestUserGroups(c *qt.C) {
	s.addUser(c, params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
		Email:      "jbloggs@example.com",
		FullName:   "Joe Bloggs",
	})
	s.addUser(c, params.User{
		Username:   "jbloggs2",
		ExternalID: "http://example.com/jbloggs2",
		Email:      "jbloggs2@example.com",
		FullName:   "Joe Bloggs II",
		IDPGroups: []string{
			"test1",
			"test2",
		},
	})

	for _, test := range userGroupTests {
		c.Run(test.about, func(c *qt.C) {
			groups, err := s.adminClient.UserGroups(s.srv.Ctx, &params.UserGroupsRequest{
				Username: test.username,
			})
			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				return
			}
			c.Assert(err, qt.Equals, nil)
			c.Assert(groups, qt.DeepEquals, test.expectGroups)
		})
	}
}

func (s *usersSuite) TestSetUserGroups(c *qt.C) {
	s.addUser(c, params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
		Email:      "jbloggs@example.com",
		FullName:   "Joe Bloggs",
		IDPGroups: []string{
			"test1",
			"test2",
		},
	})

	err := s.adminClient.SetUserGroups(s.srv.Ctx, &params.SetUserGroupsRequest{
		Username: "jbloggs",
		Groups:   params.Groups{Groups: []string{"test3", "test4"}},
	})
	c.Assert(err, qt.Equals, nil)
	groups, err := s.adminClient.UserGroups(s.srv.Ctx, &params.UserGroupsRequest{
		Username: "jbloggs",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"test3", "test4"})

	err = s.adminClient.SetUserGroups(s.srv.Ctx, &params.SetUserGroupsRequest{
		Username: "not-there",
		Groups:   params.Groups{Groups: []string{"test3", "test4"}},
	})
	c.Assert(err, qt.ErrorMatches, `Put .*/v1/u/not-there/groups: user not-there not found`)
}

var modifyUserGroupsTests = []struct {
	about        string
	startGroups  []string
	username     params.Username
	addGroups    []string
	removeGroups []string
	expectGroups []string
	expectError  string
}{{
	about:        "add groups",
	startGroups:  []string{"test1", "test2"},
	addGroups:    []string{"test3", "test4"},
	expectGroups: []string{"test1", "test2", "test3", "test4"},
}, {
	about:        "remove groups",
	startGroups:  []string{"test1", "test2"},
	removeGroups: []string{"test1", "test2"},
	expectGroups: []string{},
}, {
	about:        "add and remove groups",
	startGroups:  []string{"test1", "test2"},
	addGroups:    []string{"test3", "test4"},
	removeGroups: []string{"test1", "test2"},
	expectError:  `Post .*/v1/u/.*/groups: cannot add and remove groups in the same operation`,
}, {
	about:        "remove groups not a member of",
	startGroups:  []string{"test1", "test2"},
	removeGroups: []string{"test5"},
	expectGroups: []string{"test1", "test2"},
}, {
	about:       "user not found",
	username:    "not-there",
	addGroups:   []string{"test3", "test4"},
	expectError: `Post .*/v1/u/not-there/groups: user not-there not found`,
}}

func (s *usersSuite) TestModifyUserGroups(c *qt.C) {
	for i, test := range modifyUserGroupsTests {
		c.Run(test.about, func(c *qt.C) {
			username := params.Username(fmt.Sprintf("test-%d", i))
			if test.username == "" {
				test.username = username
			}
			s.addUser(c, params.User{
				Username:   username,
				ExternalID: "test:http://example.com/" + string(username),
				IDPGroups:  test.startGroups,
			})
			err := s.adminClient.ModifyUserGroups(s.srv.Ctx, &params.ModifyUserGroupsRequest{
				Username: test.username,
				Groups: params.ModifyGroups{
					Add:    test.addGroups,
					Remove: test.removeGroups,
				},
			})

			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				return
			}
			c.Assert(err, qt.Equals, nil)

			groups, err := s.adminClient.UserGroups(s.srv.Ctx, &params.UserGroupsRequest{
				Username: test.username,
			})
			c.Assert(err, qt.Equals, nil)
			c.Assert(groups, qt.DeepEquals, test.expectGroups)
		})
	}
}

func (s *usersSuite) TestUserIDPGroups(c *qt.C) {
	s.addUser(c, params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
		Email:      "jbloggs@example.com",
		FullName:   "Joe Bloggs",
		IDPGroups: []string{
			"test1",
			"test2",
		},
	})

	groups, err := s.adminClient.UserIDPGroups(s.srv.Ctx, &params.UserIDPGroupsRequest{
		UserGroupsRequest: params.UserGroupsRequest{
			Username: "jbloggs",
		},
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(groups, qt.DeepEquals, []string{"test1", "test2"})
}

func (s *usersSuite) TestWhoAmIWithAuthenticatedUser(c *qt.C) {
	client := s.srv.IdentityClient(c, "bob@candid")
	resp, err := client.WhoAmI(s.srv.Ctx, nil)
	c.Assert(err, qt.Equals, nil)
	c.Assert(resp.User, qt.Equals, "bob@candid")
}

func (s *usersSuite) TestWhoAmIWithNoUser(c *qt.C) {
	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: s.srv.URL,
		Client:  s.srv.Client(nil),
	})
	c.Assert(err, qt.Equals, nil)
	_, err = client.WhoAmI(s.srv.Ctx, nil)
	c.Assert(err, qt.ErrorMatches, `Get .*/v1/whoami: cannot get discharge from ".*": cannot start interactive session: interaction required but not possible`)
}

func (s *usersSuite) TestExtraInfo(c *qt.C) {
	s.addUser(c, params.User{
		Username:   "jbloggs",
		ExternalID: "http://example.com/jbloggs",
	})
	err := s.adminClient.SetUserExtraInfo(s.srv.Ctx, &params.SetUserExtraInfoRequest{
		Username: "jbloggs",
		ExtraInfo: map[string]interface{}{
			"item1": 1,
			"item2": "two",
		},
	})
	c.Assert(err, qt.Equals, nil)

	ei, err := s.adminClient.UserExtraInfo(s.srv.Ctx, &params.UserExtraInfoRequest{
		Username: "jbloggs",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(ei, qt.DeepEquals, map[string]interface{}{
		"item1": 1.0,
		"item2": "two",
	})

	err = s.adminClient.SetUserExtraInfo(s.srv.Ctx, &params.SetUserExtraInfoRequest{
		Username: "jbloggs",
		ExtraInfo: map[string]interface{}{
			"item1": 2,
			"item3": "three",
		},
	})
	c.Assert(err, qt.Equals, nil)

	ei, err = s.adminClient.UserExtraInfo(s.srv.Ctx, &params.UserExtraInfoRequest{
		Username: "jbloggs",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(ei, qt.DeepEquals, map[string]interface{}{
		"item1": 2.0,
		"item2": "two",
		"item3": "three",
	})

	item, err := s.adminClient.UserExtraInfoItem(s.srv.Ctx, &params.UserExtraInfoItemRequest{
		Username: "jbloggs",
		Item:     "item2",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(item, qt.Equals, "two")

	err = s.adminClient.SetUserExtraInfoItem(s.srv.Ctx, &params.SetUserExtraInfoItemRequest{
		Username: "jbloggs",
		Item:     "item2",
		Data:     "TWO",
	})
	c.Assert(err, qt.Equals, nil)

	ei, err = s.adminClient.UserExtraInfo(s.srv.Ctx, &params.UserExtraInfoRequest{
		Username: "jbloggs",
	})
	c.Assert(err, qt.Equals, nil)
	c.Assert(ei, qt.DeepEquals, map[string]interface{}{
		"item1": 2.0,
		"item2": "TWO",
		"item3": "three",
	})
}

func (s *usersSuite) TestExtraInfoNotFound(c *qt.C) {
	err := s.adminClient.SetUserExtraInfo(s.srv.Ctx, &params.SetUserExtraInfoRequest{
		Username: "not-there",
		ExtraInfo: map[string]interface{}{
			"item1": 1,
			"item2": "two",
		},
	})
	c.Assert(err, qt.ErrorMatches, `Put .*/v1/u/not-there/extra-info: user not-there not found`)

	_, err = s.adminClient.UserExtraInfo(s.srv.Ctx, &params.UserExtraInfoRequest{
		Username: "not-there",
	})
	c.Assert(err, qt.ErrorMatches, `Get .*/v1/u/not-there/extra-info: user not-there not found`)

	_, err = s.adminClient.UserExtraInfoItem(s.srv.Ctx, &params.UserExtraInfoItemRequest{
		Username: "not-there",
		Item:     "item2",
	})
	c.Assert(err, qt.ErrorMatches, `Get .*/v1/u/not-there/extra-info/item2: user not-there not found`)

	err = s.adminClient.SetUserExtraInfoItem(s.srv.Ctx, &params.SetUserExtraInfoItemRequest{
		Username: "not-there",
		Item:     "item2",
		Data:     "TWO",
	})
	c.Assert(err, qt.ErrorMatches, `Put .*/v1/u/not-there/extra-info/item2: user not-there not found`)
}

func (s *usersSuite) assertUser(c *qt.C, u1, u2 params.User) {
	u1.GravatarID = ""
	u1.LastLogin = nil
	u1.LastDischarge = nil
	u2.GravatarID = ""
	u2.LastLogin = nil
	u2.LastDischarge = nil
	c.Assert(len(u1.PublicKeys), qt.Equals, len(u2.PublicKeys), qt.Commentf("mismatch in public keys"))
	for i, pk := range u1.PublicKeys {
		c.Assert(pk.Key, qt.Equals, u2.PublicKeys[i].Key)
	}
	u1.PublicKeys = nil
	u2.PublicKeys = nil
	c.Assert(u1, qt.DeepEquals, u2)
}

func (s *usersSuite) addUser(c *qt.C, u params.User) {
	identity := store.Identity{
		Username:   string(u.Username),
		ProviderID: store.ProviderIdentity(u.ExternalID),
		Name:       u.FullName,
		Email:      u.Email,
		Groups:     u.IDPGroups,
		PublicKeys: publicKeys(u.PublicKeys),
	}
	if u.Owner != "" {
		// Note: this mirrors the logic in handler.SetUser.
		owner := store.Identity{
			Username: string(u.Owner),
		}
		err := s.store.Store.Identity(s.srv.Ctx, &owner)
		c.Assert(err, qt.Equals, nil)
		identity.Owner = owner.ProviderID
	}
	err := s.store.Store.UpdateIdentity(s.srv.Ctx, &identity, store.Update{
		store.Username:     store.Set,
		store.Name:         store.Set,
		store.Email:        store.Set,
		store.Groups:       store.Set,
		store.PublicKeys:   store.Set,
		store.ProviderInfo: store.Set,
		store.Owner:        store.Set,
	})
	c.Assert(err, qt.Equals, nil)
}

func publicKeys(pks []*bakery.PublicKey) []bakery.PublicKey {
	pks1 := make([]bakery.PublicKey, len(pks))
	for i, pk := range pks {
		if pk == nil {
			panic("nil public key")
		}
		pks1[i] = *pk
	}
	return pks1
}

func publicKeyPtrs(pks []bakery.PublicKey) []*bakery.PublicKey {
	pks1 := make([]*bakery.PublicKey, len(pks))
	for i, key := range pks {
		pk := key
		pks1[i] = &pk
	}
	return pks1
}
