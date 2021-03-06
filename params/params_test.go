// Copyright 2015 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package params_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/candid/v2/params"
)

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
	username:    "toolongusername_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_",
	expectError: "username longer than 256 characters",
}}

func TestUsernameTextUnmarshal(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	for _, test := range usernameUnmarshalTests {
		c.Run(test.username, func(c *qt.C) {
			u := new(params.Username)
			err := u.UnmarshalText([]byte(test.username))
			if test.expectError == "" {
				c.Assert(err, qt.IsNil)
				c.Assert(*u, qt.Equals, params.Username(test.username))
			} else {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				c.Assert(*u, qt.Equals, params.Username(""))
			}
		})
	}
}
