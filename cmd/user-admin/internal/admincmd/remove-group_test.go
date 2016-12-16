// Copyright 2016 Canonical Ltd.

package admincmd_test

import (
	"github.com/juju/idmclient/params"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
)

type removeGroupSuite struct {
	commandSuite
}

var _ = gc.Suite(&removeGroupSuite{})

func (s *removeGroupSuite) TestRemoveGroup(c *gc.C) {
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
	CheckNoOutput(c, runf, "remove-group", "-a", "admin.agent", "-u", "bob", "test1", "test2")
	c.Assert(username, gc.Equals, "bob")
	c.Assert(removeGroups, jc.DeepEquals, []string{"test1", "test2"})
	c.Assert(addGroups, jc.DeepEquals, []string{})
}

func (s *removeGroupSuite) TestRemoveGroupForEmail(c *gc.C) {
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
	CheckNoOutput(c, runf, "remove-group", "-a", "admin.agent", "-e", "bob@example.com", "test1", "test2")
	c.Assert(username, gc.Equals, "bob")
	c.Assert(removeGroups, jc.DeepEquals, []string{"test1", "test2"})
	c.Assert(addGroups, jc.DeepEquals, []string{})
}

func (s *removeGroupSuite) TestRemoveGroupForEmailNotFound(c *gc.C) {
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
		"remove-group", "-a", "admin.agent", "-e", "alice@example.com", "test1", "test2",
	)
}

func (s *removeGroupSuite) TestRemoveGroupNoUser(c *gc.C) {
	CheckError(
		c,
		2,
		`no user specified, please specify either username or email`,
		s.Run,
		"remove-group", "-a", "admin.agent", "test1", "test2",
	)
}
