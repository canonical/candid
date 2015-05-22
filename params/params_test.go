// Copyright 2015 Canonical Ltd.

package params_test

import (
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/params"
)

type paramsSuite struct{}

var _ = gc.Suite(&paramsSuite{})

var usernameUnmarshalTests = []struct {
	username    string
	expectError string
}{{
	username: "user",
}, {
	username: "admin@idm",
}, {
	username: "agent@admin@idm",
}, {
	username:    "invalid username",
	expectError: `illegal username "invalid username"`,
}, {
	username:    "toolongusername_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_",
	expectError: "username longer than 256 characters",
}}

func (s *paramsSuite) TestUsernameTextUnmarshal(c *gc.C) {
	for i, test := range usernameUnmarshalTests {
		c.Logf("%d. %s", i, test.username)
		u := new(params.Username)
		err := u.UnmarshalText([]byte(test.username))
		if test.expectError == "" {
			c.Assert(err, gc.IsNil)
			c.Assert(*u, gc.Equals, params.Username(test.username))
		} else {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			c.Assert(*u, gc.Equals, params.Username(""))
		}
	}
}
