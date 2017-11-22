// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"fmt"
	"time"

	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/juju/idmclient.v1"
	"gopkg.in/juju/idmclient.v1/params"
	"gopkg.in/macaroon-bakery.v2/bakery"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/CanonicalLtd/blues-identity/internal/auth"
	"github.com/CanonicalLtd/blues-identity/store"
)

type usersSuite struct {
	apiSuite
	adminClient *idmclient.Client
}

var _ = gc.Suite(&usersSuite{})

func (s *usersSuite) SetUpTest(c *gc.C) {
	s.apiSuite.SetUpTest(c)
	s.adminClient = s.AdminIdentityClient(c)
}

func (s *usersSuite) TestRoundTripUser(c *gc.C) {
	user := &params.User{
		Username:   "jbloggs",
		ExternalID: "test:http://example.com/jbloggs",
		FullName:   "Joe Bloggs",
		Email:      "jbloggs@example.com",
		GravatarID: "62300f8842b68279680736dc1f9fc52e",
		IDPGroups: []string{
			"test",
		},
	}
	err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: user.Username,
		User:     *user,
	})
	c.Assert(err, gc.Equals, nil)

	resp, err := s.adminClient.User(s.Ctx, &params.UserRequest{
		Username: user.Username,
	})
	c.Assert(err, gc.Equals, nil)

	s.assertUser(c, *resp, *user)
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
	username:    "bad-name-",
	expectError: `Get .*/v1/u/bad-name-: cannot unmarshal parameters: cannot unmarshal into field Username: illegal username "bad-name-"`,
}}

func (s *usersSuite) TestUserErrors(c *gc.C) {
	for i, test := range userErrorTests {
		c.Logf("test %d. %s", i, test.about)
		_, err := s.adminClient.User(s.Ctx, &params.UserRequest{
			Username: test.username,
		})
		c.Assert(err, gc.ErrorMatches, test.expectError)
	}
}

var (
	pk1 = bakery.MustGenerateKey().Public
	pk2 = bakery.MustGenerateKey().Public
)

var setUserTests = []struct {
	about      string
	user       params.User
	expectUser params.User
}{{
	about: "create user",
	user: params.User{
		Username:   "jbloggs",
		ExternalID: "test:http://example.com/jbloggs",
		FullName:   "Joe Bloggs",
		Email:      "jbloggs@example.com",
		IDPGroups: []string{
			"test1",
		},
	},
	expectUser: params.User{
		Username:   "jbloggs",
		ExternalID: "test:http://example.com/jbloggs",
		FullName:   "Joe Bloggs",
		Email:      "jbloggs@example.com",
		IDPGroups: []string{
			"test1",
		},
	},
}, {
	about: "update user",
	user: params.User{
		Username:   "jbloggsToo",
		ExternalID: "test:http://example.com/jbloggs2",
		FullName:   "Joe Bloggs The Second",
		Email:      "jbloggsii@example.com",
		IDPGroups: []string{
			"test3",
		},
	},
	expectUser: params.User{
		Username:   "jbloggsToo",
		ExternalID: "test:http://example.com/jbloggs2",
		FullName:   "Joe Bloggs The Second",
		Email:      "jbloggsii@example.com",
		IDPGroups: []string{
			"test1",
			"test3",
		},
	},
}, {
	about: "create agent",
	user: params.User{
		Username: "agent@jbloggs3",
		Owner:    "jbloggs3",
		IDPGroups: []string{
			"test1",
		},
		PublicKeys: []*bakery.PublicKey{
			&pk1,
		},
	},
	expectUser: params.User{
		Username: "agent@jbloggs3",
		Owner:    "jbloggs3",
		IDPGroups: []string{
			"test1",
		},
		PublicKeys: []*bakery.PublicKey{
			&pk1,
		},
	},
}, {
	about: "update agent",
	user: params.User{
		Username: "agent2@jbloggs3",
		Owner:    "jbloggs3",
		IDPGroups: []string{
			"test3",
		},
		PublicKeys: []*bakery.PublicKey{
			&pk2,
		},
	},
	expectUser: params.User{
		Username: "agent2@jbloggs3",
		Owner:    "jbloggs3",
		IDPGroups: []string{
			"test3",
		},
		PublicKeys: []*bakery.PublicKey{
			&pk2,
		},
	},
}}

func (s *usersSuite) TestSetUser(c *gc.C) {
	err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs2",
		User: params.User{
			ExternalID: "test:http://example.com/jbloggs2",
			FullName:   "Joe Bloggs II",
			Email:      "jbloggs2@example.com",
			IDPGroups: []string{
				"test1",
			},
		},
	})
	c.Assert(err, gc.Equals, nil)

	err = s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs3",
		User: params.User{
			ExternalID: "test:http://example.com/jbloggs3",
			FullName:   "Joe Bloggs III",
			Email:      "jbloggs3@example.com",
		},
	})
	c.Assert(err, gc.Equals, nil)

	err = s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "agent2@jbloggs2",
		User: params.User{
			Owner: "jbloggs2",
			IDPGroups: []string{
				"test1",
			},
			PublicKeys: []*bakery.PublicKey{
				&pk1,
			},
		},
	})
	c.Assert(err, gc.Equals, nil)

	for i, test := range setUserTests {
		c.Logf("test %d. %s", i, test.about)
		err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
			Username: test.user.Username,
			User:     test.user,
		})
		c.Assert(err, gc.Equals, nil)
		u, err := s.adminClient.User(s.Ctx, &params.UserRequest{
			Username: test.user.Username,
		})
		c.Assert(err, gc.Equals, nil)
		s.assertUser(c, *u, test.expectUser)
	}
}

var setUserErrorTests = []struct {
	about       string
	user        params.User
	expectError string
}{{
	about: "bad username",
	user: params.User{
		Username: "bad-name-",
	},
	expectError: `Put .*/v1/u/bad-name-: cannot unmarshal parameters: cannot unmarshal into field Username: illegal username "bad-name-"`,
}, {
	about: "name in use",
	user: params.User{
		Username:   "jbloggs2",
		ExternalID: "test:http://example.com/jbloggs",
	},
	expectError: `Put .*/v1/u/jbloggs2: username jbloggs2 already in use`,
}, {
	about: "no external_id",
	user: params.User{
		Username: "jbloggs",
	},
	expectError: `Put .*/v1/u/jbloggs: external_id not specified`,
}, {
	about: "external_id and owner",
	user: params.User{
		Username:   "jbloggs@bob",
		ExternalID: "test:http://example.com/jbloggs",
		Owner:      "bob",
	},
	expectError: `Put .*/v1/u/jbloggs@bob: both owner and external_id specified`,
}, {
	about: "reserved name",
	user: params.User{
		Username:   "everyone",
		ExternalID: "test:http://example.com/jbloggs",
	},
	expectError: `Put .*/v1/u/everyone: username "everyone" is reserved`,
}, {
	about: "invalid agent name",
	user: params.User{
		Username: "agent",
		Owner:    "bob",
	},
	expectError: `Put .*/v1/u/agent: bob cannot create user "agent" \(suffix must be "@bob"\)`,
}, {
	about: "agent owner doesn't exist",
	user: params.User{
		Username: "agent@alice",
		Owner:    "alice",
	},
	expectError: `Put .*/v1/u/agent@alice: owner must exist`,
}}

func (s *usersSuite) TestSetUserErrors(c *gc.C) {
	err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs2",
		User: params.User{
			Username:   "jbloggs2",
			ExternalID: "test:http://example.com/jbloggs2",
			FullName:   "Joe Bloggs II",
			Email:      "jbloggs2@example.com",
			IDPGroups: []string{
				"test1",
			},
		},
	})
	c.Assert(err, gc.Equals, nil)

	for i, test := range setUserErrorTests {
		c.Logf("test %d. %s", i, test.about)
		err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
			Username: test.user.Username,
			User:     test.user,
		})
		c.Assert(err, gc.ErrorMatches, test.expectError)
	}
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

func (s *usersSuite) TestQueryUsers(c *gc.C) {
	err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs2",
		User: params.User{
			Username:   "jbloggs2",
			ExternalID: "test:http://example.com/jbloggs2",
			Email:      "jbloggs2@example.com",
			FullName:   "Joe Bloggs II",
			IDPGroups: []string{
				"test",
			},
		},
	})
	c.Assert(err, gc.Equals, nil)
	err = s.Params.Store.UpdateIdentity(
		s.Ctx,
		&store.Identity{
			Username:      "jbloggs2",
			LastLogin:     time.Now().AddDate(0, 0, -29),
			LastDischarge: time.Now().AddDate(0, 0, -14),
		},
		store.Update{
			store.LastLogin:     store.Set,
			store.LastDischarge: store.Set,
		},
	)
	c.Assert(err, gc.Equals, nil)
	for i, test := range queryUserTests {
		c.Logf("test %d. %s", i, test.about)
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
		users, err := s.adminClient.QueryUsers(s.Ctx, &req)
		c.Assert(err, gc.Equals, nil)
		c.Assert(users, jc.DeepEquals, test.expect)
	}
}

func (s *usersSuite) TestQueryUsersBadLastLogin(c *gc.C) {
	_, err := s.adminClient.QueryUsers(s.Ctx, &params.QueryUsersRequest{
		LastLoginSince: "yesterday",
	})
	c.Assert(err, gc.ErrorMatches, `Get http://.*/v1/u?.*last-login-since=yesterday.*: cannot unmarshal last-login-since: parsing time "yesterday" as "2006-01-02T15:04:05Z07:00": cannot parse "yesterday" as "2006"`)
}

func (s *usersSuite) TestQueryUsersBadLastDischarge(c *gc.C) {
	_, err := s.adminClient.QueryUsers(s.Ctx, &params.QueryUsersRequest{
		LastDischargeSince: "yesterday",
	})
	c.Assert(err, gc.ErrorMatches, `Get http://.*/v1/u?.*last-discharge-since=yesterday.*: cannot unmarshal last-discharge-since: parsing time "yesterday" as "2006-01-02T15:04:05Z07:00": cannot parse "yesterday" as "2006"`)
}

func (s *usersSuite) TestQueryUsersUnauthorized(c *gc.C) {
	client := s.IdentityClient(c, "bob@admin@idm", "admin@idm", "bob")
	_, err := client.QueryUsers(s.Ctx, &params.QueryUsersRequest{})
	c.Assert(err, gc.ErrorMatches, `Get http://.*/v1/u?.*: permission denied`)
}

func (s *usersSuite) TestSSHKeys(c *gc.C) {
	err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs",
		User: params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		},
	})
	c.Assert(err, gc.Equals, nil)

	// Check there is no ssh key for the user.
	sshKeys, err := s.adminClient.GetSSHKeys(s.Ctx, &params.SSHKeysRequest{
		Username: "jbloggs",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(sshKeys.SSHKeys, jc.DeepEquals, []string(nil))

	// Add ssh keys to the user.
	err = s.adminClient.PutSSHKeys(s.Ctx, &params.PutSSHKeysRequest{
		Username: "jbloggs",
		Body: params.PutSSHKeysBody{
			SSHKeys: []string{"36ASDER56", "22ERT56DG", "56ASDFASDF32"},
			Add:     false,
		},
	})
	c.Assert(err, gc.Equals, nil)

	// Check it is present.
	sshKeys, err = s.adminClient.GetSSHKeys(s.Ctx, &params.SSHKeysRequest{
		Username: "jbloggs",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(sshKeys.SSHKeys, jc.DeepEquals, []string{
		"36ASDER56",
		"22ERT56DG",
		"56ASDFASDF32",
	})

	// Remove some ssh keys.
	err = s.adminClient.DeleteSSHKeys(s.Ctx, &params.DeleteSSHKeysRequest{
		Username: "jbloggs",
		Body: params.DeleteSSHKeysBody{
			SSHKeys: []string{"22ERT56DG", "56ASDFASDF32"},
		},
	})
	c.Assert(err, gc.Equals, nil)

	// Check we only get one.
	sshKeys, err = s.adminClient.GetSSHKeys(s.Ctx, &params.SSHKeysRequest{
		Username: "jbloggs",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(sshKeys.SSHKeys, jc.DeepEquals, []string{
		"36ASDER56",
	})

	// Delete an unknown ssh key just do nothing silently.
	err = s.adminClient.DeleteSSHKeys(s.Ctx, &params.DeleteSSHKeysRequest{
		Username: "jbloggs",
		Body: params.DeleteSSHKeysBody{
			SSHKeys: []string{"22ERT56DG"},
		},
	})
	c.Assert(err, gc.Equals, nil)

	// Check we only get one.
	sshKeys, err = s.adminClient.GetSSHKeys(s.Ctx, &params.SSHKeysRequest{
		Username: "jbloggs",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(sshKeys.SSHKeys, jc.DeepEquals, []string{
		"36ASDER56",
	})

	// Append one ssh key.
	err = s.adminClient.PutSSHKeys(s.Ctx, &params.PutSSHKeysRequest{
		Username: "jbloggs",
		Body: params.PutSSHKeysBody{
			SSHKeys: []string{"90SDFGS45"},
			Add:     true,
		},
	})
	c.Assert(err, gc.Equals, nil)

	// Check we get two.
	sshKeys, err = s.adminClient.GetSSHKeys(s.Ctx, &params.SSHKeysRequest{
		Username: "jbloggs",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(sshKeys.SSHKeys, jc.DeepEquals, []string{
		"36ASDER56",
		"90SDFGS45",
	})
}

func (s *usersSuite) TestVerifyUserToken(c *gc.C) {
	err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs",
		User: params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		},
	})
	c.Assert(err, gc.Equals, nil)

	m, err := s.adminClient.UserToken(s.Ctx, &params.UserTokenRequest{
		Username: "jbloggs",
	})
	c.Assert(err, gc.Equals, nil)

	declared, err := s.adminClient.VerifyToken(s.Ctx, &params.VerifyTokenRequest{
		Macaroons: macaroon.Slice{m.M()},
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(declared, jc.DeepEquals, map[string]string{
		"username": "jbloggs",
	})

	badm, err := macaroon.New([]byte{}, []byte("no such macaroon"), "loc", macaroon.LatestVersion)
	c.Assert(err, gc.Equals, nil)
	_, err = s.adminClient.VerifyToken(s.Ctx, &params.VerifyTokenRequest{
		Macaroons: macaroon.Slice{badm},
	})
	c.Assert(err, gc.ErrorMatches, `Post .*/v1/verify: verification failure: macaroon discharge required: authentication required`)
}

func (s *usersSuite) TestUserTokenNotFound(c *gc.C) {
	_, err := s.adminClient.UserToken(s.Ctx, &params.UserTokenRequest{
		Username: "not-there",
	})
	c.Assert(err, gc.ErrorMatches, `Get .*/v1/u/not-there/macaroon: user not-there not found`)
}

func (s *usersSuite) TestDischargeToken(c *gc.C) {
	err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs",
		User: params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test",
			},
		},
	})
	c.Assert(err, gc.Equals, nil)

	client := &httprequest.Client{
		BaseURL: s.URL,
		Doer:    s.AdminClient(),
	}
	var resp params.DischargeTokenForUserResponse
	err = client.Get(s.Ctx, "/v1/discharge-token-for-user?username=jbloggs", &resp)
	c.Assert(err, gc.Equals, nil)

	declared, err := s.adminClient.VerifyToken(s.Ctx, &params.VerifyTokenRequest{
		Macaroons: macaroon.Slice{resp.DischargeToken.M()},
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(declared, jc.DeepEquals, map[string]string{
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

func (s *usersSuite) TestUserGroups(c *gc.C) {
	err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs",
		User: params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
		},
	})
	c.Assert(err, gc.Equals, nil)

	err = s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs2",
		User: params.User{
			Username:   "jbloggs2",
			ExternalID: "http://example.com/jbloggs2",
			Email:      "jbloggs2@example.com",
			FullName:   "Joe Bloggs II",
			IDPGroups: []string{
				"test1",
				"test2",
			},
		},
	})
	c.Assert(err, gc.Equals, nil)

	for i, test := range userGroupTests {
		c.Logf("test %d. %s", i, test.about)
		groups, err := s.adminClient.UserGroups(s.Ctx, &params.UserGroupsRequest{
			Username: test.username,
		})
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			continue
		}
		c.Assert(err, gc.Equals, nil)
		c.Assert(groups, jc.DeepEquals, test.expectGroups)
	}
}

func (s *usersSuite) TestSetUserGroups(c *gc.C) {
	err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs",
		User: params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test1",
				"test2",
			},
		},
	})
	c.Assert(err, gc.Equals, nil)

	err = s.adminClient.SetUserGroups(s.Ctx, &params.SetUserGroupsRequest{
		Username: "jbloggs",
		Groups:   params.Groups{Groups: []string{"test3", "test4"}},
	})
	c.Assert(err, gc.Equals, nil)
	groups, err := s.adminClient.UserGroups(s.Ctx, &params.UserGroupsRequest{
		Username: "jbloggs",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(groups, jc.DeepEquals, []string{"test3", "test4"})

	err = s.adminClient.SetUserGroups(s.Ctx, &params.SetUserGroupsRequest{
		Username: "not-there",
		Groups:   params.Groups{Groups: []string{"test3", "test4"}},
	})
	c.Assert(err, gc.ErrorMatches, `Put .*/v1/u/not-there/groups: user not-there not found`)
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

func (s *usersSuite) TestModifyUserGroups(c *gc.C) {
	for i, test := range modifyUserGroupsTests {
		c.Logf("test %d. %s", i, test.about)
		username := params.Username(fmt.Sprintf("test-%d", i))
		if test.username == "" {
			test.username = username
		}
		err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
			Username: username,
			User: params.User{
				ExternalID: "test:http://example.com/" + string(username),
				IDPGroups:  test.startGroups,
			},
		})
		c.Assert(err, gc.Equals, nil)

		err = s.adminClient.ModifyUserGroups(s.Ctx, &params.ModifyUserGroupsRequest{
			Username: test.username,
			Groups: params.ModifyGroups{
				Add:    test.addGroups,
				Remove: test.removeGroups,
			},
		})

		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			continue
		}
		c.Assert(err, gc.Equals, nil)

		groups, err := s.adminClient.UserGroups(s.Ctx, &params.UserGroupsRequest{
			Username: test.username,
		})
		c.Assert(err, gc.Equals, nil)
		c.Assert(groups, jc.DeepEquals, test.expectGroups)
	}
}

func (s *usersSuite) TestUserIDPGroups(c *gc.C) {
	err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs",
		User: params.User{
			Username:   "jbloggs",
			ExternalID: "http://example.com/jbloggs",
			Email:      "jbloggs@example.com",
			FullName:   "Joe Bloggs",
			IDPGroups: []string{
				"test1",
				"test2",
			},
		},
	})
	c.Assert(err, gc.Equals, nil)

	groups, err := s.adminClient.UserIDPGroups(s.Ctx, &params.UserIDPGroupsRequest{
		UserGroupsRequest: params.UserGroupsRequest{
			Username: "jbloggs",
		},
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(groups, jc.DeepEquals, []string{"test1", "test2"})
}

func (s *usersSuite) TestWhoAmIWithAuthenticatedUser(c *gc.C) {
	client := s.IdentityClient(c, "bob", "admin@idm")
	resp, err := client.WhoAmI(s.Ctx, nil)
	c.Assert(err, gc.Equals, nil)
	c.Assert(resp.User, gc.Equals, "bob@admin@idm")
}

func (s *usersSuite) TestWhoAmIWithNoUser(c *gc.C) {
	client, err := idmclient.New(idmclient.NewParams{
		BaseURL: s.URL,
		Client:  s.Client(nil),
	})
	c.Assert(err, gc.Equals, nil)
	_, err = client.WhoAmI(s.Ctx, nil)
	c.Assert(err, gc.ErrorMatches, `Get .*/v1/whoami: cannot get discharge from ".*": cannot start interactive session: interaction required but not possible`)
}

func (s *usersSuite) TestExtraInfo(c *gc.C) {
	err := s.adminClient.SetUser(s.Ctx, &params.SetUserRequest{
		Username: "jbloggs",
		User: params.User{
			ExternalID: "http://example.com/jbloggs",
		},
	})
	c.Assert(err, gc.Equals, nil)

	err = s.adminClient.SetUserExtraInfo(s.Ctx, &params.SetUserExtraInfoRequest{
		Username: "jbloggs",
		ExtraInfo: map[string]interface{}{
			"item1": 1,
			"item2": "two",
		},
	})
	c.Assert(err, gc.Equals, nil)

	ei, err := s.adminClient.UserExtraInfo(s.Ctx, &params.UserExtraInfoRequest{
		Username: "jbloggs",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(ei, jc.DeepEquals, map[string]interface{}{
		"item1": 1.0,
		"item2": "two",
	})

	err = s.adminClient.SetUserExtraInfo(s.Ctx, &params.SetUserExtraInfoRequest{
		Username: "jbloggs",
		ExtraInfo: map[string]interface{}{
			"item1": 2,
			"item3": "three",
		},
	})
	c.Assert(err, gc.Equals, nil)

	ei, err = s.adminClient.UserExtraInfo(s.Ctx, &params.UserExtraInfoRequest{
		Username: "jbloggs",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(ei, jc.DeepEquals, map[string]interface{}{
		"item1": 2.0,
		"item2": "two",
		"item3": "three",
	})

	item, err := s.adminClient.UserExtraInfoItem(s.Ctx, &params.UserExtraInfoItemRequest{
		Username: "jbloggs",
		Item:     "item2",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(item, gc.Equals, "two")

	err = s.adminClient.SetUserExtraInfoItem(s.Ctx, &params.SetUserExtraInfoItemRequest{
		Username: "jbloggs",
		Item:     "item2",
		Data:     "TWO",
	})
	c.Assert(err, gc.Equals, nil)

	ei, err = s.adminClient.UserExtraInfo(s.Ctx, &params.UserExtraInfoRequest{
		Username: "jbloggs",
	})
	c.Assert(err, gc.Equals, nil)
	c.Assert(ei, jc.DeepEquals, map[string]interface{}{
		"item1": 2.0,
		"item2": "TWO",
		"item3": "three",
	})
}

func (s *usersSuite) TestExtraInfoNotFound(c *gc.C) {
	err := s.adminClient.SetUserExtraInfo(s.Ctx, &params.SetUserExtraInfoRequest{
		Username: "not-there",
		ExtraInfo: map[string]interface{}{
			"item1": 1,
			"item2": "two",
		},
	})
	c.Assert(err, gc.ErrorMatches, `Put .*/v1/u/not-there/extra-info: user not-there not found`)

	_, err = s.adminClient.UserExtraInfo(s.Ctx, &params.UserExtraInfoRequest{
		Username: "not-there",
	})
	c.Assert(err, gc.ErrorMatches, `Get .*/v1/u/not-there/extra-info: user not-there not found`)

	_, err = s.adminClient.UserExtraInfoItem(s.Ctx, &params.UserExtraInfoItemRequest{
		Username: "not-there",
		Item:     "item2",
	})
	c.Assert(err, gc.ErrorMatches, `Get .*/v1/u/not-there/extra-info/item2: user not-there not found`)

	err = s.adminClient.SetUserExtraInfoItem(s.Ctx, &params.SetUserExtraInfoItemRequest{
		Username: "not-there",
		Item:     "item2",
		Data:     "TWO",
	})
	c.Assert(err, gc.ErrorMatches, `Put .*/v1/u/not-there/extra-info/item2: user not-there not found`)
}

func (s *usersSuite) assertUser(c *gc.C, u1, u2 params.User) {
	u1.GravatarID = ""
	u1.LastLogin = nil
	u1.LastDischarge = nil
	u2.GravatarID = ""
	u2.LastLogin = nil
	u2.LastDischarge = nil
	c.Assert(len(u1.PublicKeys), gc.Equals, len(u2.PublicKeys), gc.Commentf("mismatch in public keys"))
	for i, pk := range u1.PublicKeys {
		c.Assert(pk.Key, gc.Equals, u2.PublicKeys[i].Key)
	}
	u1.PublicKeys = nil
	u2.PublicKeys = nil
	c.Assert(u1, gc.DeepEquals, u2)
}
