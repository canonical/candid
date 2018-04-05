// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"encoding/json"
	"time"

	jc "github.com/juju/testing/checkers"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	gc "gopkg.in/check.v1"
)

type findSuite struct {
	commandSuite
}

var _ = gc.Suite(&findSuite{})

func (s *findSuite) TestFindEmail(c *gc.C) {
	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			if req.Email == "bob@example.com" {
				return []string{"bob"}, nil
			}
			return []string{}, nil
		},
	})
	stdout := CheckSuccess(c, runf, "find", "-a", "admin.agent", "-e", "bob@example.com")
	c.Assert(stdout, gc.Equals, "bob\n")
}

func (s *findSuite) TestFindEmailNotFound(c *gc.C) {
	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			if req.Email == "alice@example.com" {
				return []string{"alice"}, nil
			}
			return []string{}, nil
		},
	})
	stdout := CheckSuccess(c, runf, "find", "-a", "admin.agent", "-e", "bob@example.com")
	c.Assert(stdout, gc.Equals, "\n")
}

func (s *findSuite) TestFindNoParameters(c *gc.C) {

	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			return []string{"alice", "bob", "charlie"}, nil
		},
	})
	stdout := CheckSuccess(c, runf, "find", "-a", "admin.agent", "--format", "json")
	var usernames []string
	err := json.Unmarshal([]byte(stdout), &usernames)
	c.Assert(err, gc.Equals, nil)
	c.Assert(usernames, jc.DeepEquals, []string{"alice", "bob", "charlie"})
}

func (s *findSuite) TestFindLastLoginTime(c *gc.C) {
	var gotTime time.Time
	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			if err := gotTime.UnmarshalText([]byte(req.LastLoginSince)); err != nil {
				return nil, err
			}
			return []string{"alice", "bob", "charlie"}, nil
		},
	})
	stdout := CheckSuccess(c, runf, "find", "-a", "admin.agent", "--format", "json", "--last-login", "30")
	var usernames []string
	err := json.Unmarshal([]byte(stdout), &usernames)
	c.Assert(err, gc.Equals, nil)
	c.Assert(usernames, jc.DeepEquals, []string{"alice", "bob", "charlie"})
	t := time.Now().AddDate(0, 0, -30)
	c.Assert(t.Sub(gotTime), jc.LessThan, time.Second)
}

func (s *findSuite) TestFindLastDischargeTime(c *gc.C) {
	var gotTime time.Time
	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			if err := gotTime.UnmarshalText([]byte(req.LastDischargeSince)); err != nil {
				return nil, err
			}
			return []string{"alice", "bob", "charlie"}, nil
		},
	})
	stdout := CheckSuccess(c, runf, "find", "-a", "admin.agent", "--format", "json", "--last-discharge", "20")
	var usernames []string
	err := json.Unmarshal([]byte(stdout), &usernames)
	c.Assert(err, gc.Equals, nil)
	c.Assert(usernames, jc.DeepEquals, []string{"alice", "bob", "charlie"})
	t := time.Now().AddDate(0, 0, -20)
	c.Assert(t.Sub(gotTime), jc.LessThan, time.Second)
}

func (s *findSuite) TestFindWithEmail(c *gc.C) {
	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			return []string{"alice", "bob", "charlie"}, nil
		},
		user: func(req *params.UserRequest) (*params.User, error) {
			return &params.User{
				Username: req.Username,
				Email:    string(req.Username) + "@example.com",
			}, nil
		},
	})
	stdout := CheckSuccess(c, runf, "find", "-a", "admin.agent", "-d", "email", "--format", "json")
	var usernames []map[string]string
	err := json.Unmarshal([]byte(stdout), &usernames)
	c.Assert(err, gc.Equals, nil)
	c.Assert(usernames, jc.DeepEquals, []map[string]string{
		map[string]string{"username": "alice", "email": "alice@example.com"},
		map[string]string{"username": "bob", "email": "bob@example.com"},
		map[string]string{"username": "charlie", "email": "charlie@example.com"},
	})
}

func (s *findSuite) TestFindWithEmailAndGravatar(c *gc.C) {
	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			return []string{"alice", "bob", "charlie"}, nil
		},
		user: func(req *params.UserRequest) (*params.User, error) {
			return &params.User{
				Username:   req.Username,
				Email:      string(req.Username) + "@example.com",
				GravatarID: string(req.Username) + "@gravatar",
			}, nil
		},
	})
	stdout := CheckSuccess(c, runf, "find", "-a", "admin.agent", "-d", "email, gravatar_id", "--format", "json")
	var usernames []map[string]string
	err := json.Unmarshal([]byte(stdout), &usernames)
	c.Assert(err, gc.Equals, nil)
	c.Assert(usernames, jc.DeepEquals, []map[string]string{
		map[string]string{"username": "alice", "email": "alice@example.com", "gravatar_id": "alice@gravatar"},
		map[string]string{"username": "bob", "email": "bob@example.com", "gravatar_id": "bob@gravatar"},
		map[string]string{"username": "charlie", "email": "charlie@example.com", "gravatar_id": "charlie@gravatar"},
	})
}
