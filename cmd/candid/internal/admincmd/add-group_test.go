// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	jc "github.com/juju/testing/checkers"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	gc "gopkg.in/check.v1"
)

type addGroupSuite struct {
	commandSuite
}

var _ = gc.Suite(&addGroupSuite{})

func (s *addGroupSuite) TestAddGroup(c *gc.C) {
	var addGroups []string
	var removeGroups []string
	var username string
	runf := s.RunServer(c, &handler{
		modifyGroups: func(req *params.ModifyUserGroupsRequest) error {
			username = string(req.Username)
			addGroups = req.Groups.Add
			removeGroups = req.Groups.Remove
			return nil
		},
	})
	CheckNoOutput(c, runf, "add-group", "-a", "admin.agent", "-u", "bob", "test1", "test2")
	c.Assert(username, gc.Equals, "bob")
	c.Assert(addGroups, jc.DeepEquals, []string{"test1", "test2"})
	c.Assert(removeGroups, jc.DeepEquals, []string{})
}

func (s *addGroupSuite) TestAddGroupForEmail(c *gc.C) {
	var addGroups []string
	var removeGroups []string
	var username string
	runf := s.RunServer(c, &handler{
		modifyGroups: func(req *params.ModifyUserGroupsRequest) error {
			username = string(req.Username)
			addGroups = req.Groups.Add
			removeGroups = req.Groups.Remove
			return nil
		},
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			if req.Email == "bob@example.com" {
				return []string{"bob"}, nil
			}
			return []string{}, nil
		},
	})
	CheckNoOutput(c, runf, "add-group", "-a", "admin.agent", "-e", "bob@example.com", "test1", "test2")
	c.Assert(username, gc.Equals, "bob")
	c.Assert(addGroups, jc.DeepEquals, []string{"test1", "test2"})
	c.Assert(removeGroups, jc.DeepEquals, []string{})
}

func (s *addGroupSuite) TestAddGroupForEmailNotFound(c *gc.C) {
	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			if req.Email == "bob@example.com" {
				return []string{"bob"}, nil
			}
			return []string{}, nil
		},
	})
	CheckError(
		c,
		1,
		`no user found for email "alice@example.com"`,
		runf,
		"add-group", "-a", "admin.agent", "-e", "alice@example.com", "test1", "test2",
	)
}

func (s *addGroupSuite) TestAddGroupForEmailMultipleUsers(c *gc.C) {
	runf := s.RunServer(c, &handler{
		queryUsers: func(req *params.QueryUsersRequest) ([]string, error) {
			if req.Email == "bob@example.com" {
				return []string{
					"bob",
					"alice",
				}, nil
			}
			return []string{}, nil
		},
	})
	CheckError(
		c,
		1,
		`more than one user found with email "bob@example.com" \(bob, alice\)`,
		runf,
		"add-group", "-a", "admin.agent", "-e", "bob@example.com", "test1", "test2",
	)
}

func (s *addGroupSuite) TestAddGroupNoUser(c *gc.C) {
	CheckError(
		c,
		2,
		`no user specified, please specify either username or email`,
		s.Run,
		"add-group", "-a", "admin.agent", "test1", "test2",
	)
}

func (s *addGroupSuite) TestAddGroupUserAndEmail(c *gc.C) {
	CheckError(
		c,
		2,
		`both username and email specified, please specify either username or email`,
		s.Run,
		"add-group", "-a", "admin.agent", "-u", "bob", "-e", "bob@example.com", "test1", "test2",
	)
}
