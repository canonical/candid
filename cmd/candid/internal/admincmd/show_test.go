// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"path/filepath"
	"time"

	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
)

type showSuite struct {
	commandSuite
}

var _ = gc.Suite(&showSuite{})

func (s *showSuite) TestShowUserWithAgentEnv(c *gc.C) {
	// This test acts as a proxy agent-env functionality in all the
	// other command that use NewClient.
	runf := s.RunServer(c, &handler{
		user: func(req *params.UserRequest) (*params.User, error) {
			if req.Username == "bob" {
				return &params.User{
					Username: "bob",
				}, nil
			}
			return nil, errgo.New("unknown user")
		},
	})
	s.PatchEnvironment("BAKERY_AGENT_FILE", filepath.Join(s.Dir, "admin.agent"))
	stdout := CheckSuccess(c, runf, "show", "-u", "bob")
	c.Assert(stdout, gc.Equals, `
username: bob
groups: []
ssh-keys: []
last-login: never
last-discharge: never
`[1:])
}

func (s *showSuite) TestShowUser(c *gc.C) {
	t := time.Date(2016, 12, 25, 0, 0, 0, 0, time.UTC)
	runf := s.RunServer(c, &handler{
		user: func(req *params.UserRequest) (*params.User, error) {
			if req.Username == "bob" {
				return &params.User{
					Username:      "bob",
					ExternalID:    "https://example.com/bob",
					FullName:      "Bob Robertson",
					Email:         "bob@example.com",
					IDPGroups:     []string{"g1", "g2"},
					SSHKeys:       []string{"key1", "key2"},
					LastLogin:     &t,
					LastDischarge: &t,
				}, nil
			}
			return nil, errgo.New("unknown user")
		},
	})
	stdout := CheckSuccess(c, runf, "show", "-a", "admin.agent", "-u", "bob")
	c.Assert(stdout, gc.Equals, `
username: bob
external-id: https://example.com/bob
name: Bob Robertson
email: bob@example.com
groups:
- g1
- g2
ssh-keys:
- key1
- key2
last-login: "2016-12-25T00:00:00Z"
last-discharge: "2016-12-25T00:00:00Z"
`[1:])
}

func (s *showSuite) TestShowEmail(c *gc.C) {
	t := time.Date(2016, 12, 25, 0, 0, 0, 0, time.UTC)
	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			if req.Email == "bob@example.com" {
				return []string{"bob"}, nil
			}
			return []string{}, nil
		},
		user: func(req *params.UserRequest) (*params.User, error) {
			if req.Username == "bob" {
				return &params.User{
					Username:      "bob",
					ExternalID:    "https://example.com/bob",
					FullName:      "Bob Robertson",
					Email:         "bob@example.com",
					IDPGroups:     []string{"g1", "g2"},
					SSHKeys:       []string{"key1", "key2"},
					LastLogin:     &t,
					LastDischarge: &t,
				}, nil
			}
			return nil, errgo.New("unknown user")
		},
	})
	stdout := CheckSuccess(c, runf, "show", "-a", "admin.agent", "-e", "bob@example.com")
	c.Assert(stdout, gc.Equals, `
username: bob
external-id: https://example.com/bob
name: Bob Robertson
email: bob@example.com
groups:
- g1
- g2
ssh-keys:
- key1
- key2
last-login: "2016-12-25T00:00:00Z"
last-discharge: "2016-12-25T00:00:00Z"
`[1:])
}

func (s *showSuite) TestShowEmailNotFound(c *gc.C) {
	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			if req.Email == "alice@example.com" {
				return []string{"alice"}, nil
			}
			return []string{}, nil
		},
	})
	CheckError(c, 1, `no user found for email "bob@example.com"`, runf, "show", "-a", "admin.agent", "-e", "bob@example.com")
}

func (s *showSuite) TestShowNoParameters(c *gc.C) {
	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			return []string{"alice", "bob", "charlie"}, nil
		},
	})
	CheckError(c, 2, `no user specified, please specify either username or email`, runf, "show")
}

func (s *showSuite) TestShowAgentUser(c *gc.C) {
	t := time.Date(2016, 12, 25, 0, 0, 0, 0, time.UTC)
	var pk bakery.PublicKey
	runf := s.RunServer(c, &handler{
		user: func(req *params.UserRequest) (*params.User, error) {
			if req.Username == "bob@alice" {
				return &params.User{
					Username:      "bob@alice",
					Owner:         "alice",
					PublicKeys:    []*bakery.PublicKey{&pk},
					IDPGroups:     []string{"g1", "g2"},
					SSHKeys:       []string{"key1", "key2"},
					LastLogin:     &t,
					LastDischarge: &t,
				}, nil
			}
			return nil, errgo.New("unknown user")
		},
	})
	stdout := CheckSuccess(c, runf, "show", "-a", "admin.agent", "-u", "bob@alice")
	c.Assert(stdout, gc.Equals, `
username: bob@alice
owner: alice
public-keys:
- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
groups:
- g1
- g2
ssh-keys:
- key1
- key2
last-login: "2016-12-25T00:00:00Z"
last-discharge: "2016-12-25T00:00:00Z"
`[1:])
}

func (s *showSuite) TestShowZeroValues(c *gc.C) {
	var t time.Time
	runf := s.RunServer(c, &handler{
		user: func(req *params.UserRequest) (*params.User, error) {
			if req.Username == "bob" {
				return &params.User{
					Username:   "bob",
					ExternalID: "https://example.com/bob",
					LastLogin:  &t,
				}, nil
			}
			return nil, errgo.New("unknown user")
		},
	})
	stdout := CheckSuccess(c, runf, "show", "-a", "admin.agent", "-u", "bob")
	c.Assert(stdout, gc.Equals, `
username: bob
external-id: https://example.com/bob
name: ""
email: ""
groups: []
ssh-keys: []
last-login: never
last-discharge: never
`[1:])
}

func (s *showSuite) TestShowUserError(c *gc.C) {
	runf := s.RunServer(c, &handler{
		user: func(req *params.UserRequest) (*params.User, error) {
			return nil, errgo.WithCausef(nil, httpbakery.ErrBadRequest, "unknown user %q", req.Username)
		},
	})
	CheckError(c, 1, `Get https://.*/v1/u/bob: unknown user "bob"`, runf, "show", "-a", "admin.agent", "-u", "bob")
}

func (s *showSuite) TestShowUserJSON(c *gc.C) {
	t := time.Date(2016, 12, 25, 0, 0, 0, 0, time.UTC)
	runf := s.RunServer(c, &handler{
		user: func(req *params.UserRequest) (*params.User, error) {
			if req.Username == "bob" {
				return &params.User{
					Username:      "bob",
					ExternalID:    "https://example.com/bob",
					FullName:      "Bob Robertson",
					Email:         "bob@example.com",
					IDPGroups:     []string{"g1", "g2"},
					SSHKeys:       []string{"key1", "key2"},
					LastLogin:     &t,
					LastDischarge: &t,
				}, nil
			}
			return nil, errgo.New("unknown user")
		},
	})
	stdout := CheckSuccess(c, runf, "show", "-a", "admin.agent", "-u", "bob", "--format", "json")
	c.Assert(stdout, gc.Equals, `
{"username":"bob","external-id":"https://example.com/bob","name":"Bob Robertson","email":"bob@example.com","groups":["g1","g2"],"ssh-keys":["key1","key2"],"last-login":"2016-12-25T00:00:00Z","last-discharge":"2016-12-25T00:00:00Z"}
`[1:])
}
