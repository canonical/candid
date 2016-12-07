// Copyright 2016 Canonical Ltd.

package admincmd_test

import (
	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	gc "gopkg.in/check.v1"
)

type findSuite struct {
	commandSuite
}

var _ = gc.Suite(&findSuite{})

func (s *findSuite) TestFindEmail(c *gc.C) {
	bakeryService := newBakery()
	runf := s.RunServer(c, []httprequest.Handler{
		queryUsersHandler(bakeryService, func(req *params.QueryUsersRequest) ([]string, error) {
			if req.Email == "bob@example.com" {
				return []string{"bob"}, nil
			}
			return []string{}, nil
		}),
	})
	stdout := CheckSuccess(c, runf, "find", "-a", "admin.agent", "-e", "bob@example.com")
	c.Assert(stdout, gc.Equals, "bob\n")
}

func (s *findSuite) TestAddGroupForEmailNotFound(c *gc.C) {
	bakeryService := newBakery()
	runf := s.RunServer(c, []httprequest.Handler{
		queryUsersHandler(bakeryService, func(req *params.QueryUsersRequest) ([]string, error) {
			if req.Email == "bob@example.com" {
				return []string{"bob"}, nil
			}
			return []string{}, nil
		}),
	})
	CheckError(
		c,
		1,
		`no user found for email "alice@example.com"`,
		runf,
		"find", "-a", "admin.agent", "-e", "alice@example.com",
	)
}

func (s *findSuite) TestFindNoUser(c *gc.C) {
	CheckError(
		c,
		2,
		`no user specified, please specify either username or email`,
		s.Run,
		"find", "-a", "admin.agent",
	)
}
