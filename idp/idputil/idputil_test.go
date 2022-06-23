// Copyright 2022 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package idputil_test

import (
	"testing"

	"github.com/canonical/candid/idp/idputil"
	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var writeGroupsToCSVTests = []struct {
	name   string
	groups []string
	expect string
}{{
	name:   "Write groups",
	groups: []string{"group1", "group2", "group-3", "group 4"},
	expect: "group1,group2,group-3,group 4\n",
}, {
	name:   "Write a nil",
	groups: nil,
	expect: "",
}, {
	name:   "Write an empty array",
	groups: []string{},
	expect: "",
}}

func TestWriteGroupsToCSV(t *testing.T) {
	c := qt.New(t)

	for _, test := range writeGroupsToCSVTests {
		c.Run(test.name, func(c *qt.C) {
			actual, err := idputil.WriteGroupsToCSV(test.groups)
			c.Assert(err, qt.IsNil)
			c.Check(actual, qt.CmpEquals(cmpopts.EquateEmpty()), test.expect)
		})
	}
}

var readGroupsFromCSVTests = []struct {
	name   string
	groups string
	expect []string
}{{
	name:   "Read groups",
	groups: "group1,group2,group-3,group 4\n",
	expect: []string{"group1", "group2", "group-3", "group 4"},
}, {
	name:   "Read an empty string",
	groups: "",
	expect: nil,
}, {
	name:   "Read a new line character",
	groups: "\n",
	expect: nil,
}}

func TestReadGroupsFromCSV(t *testing.T) {
	c := qt.New(t)

	for _, test := range readGroupsFromCSVTests {
		c.Run(test.name, func(c *qt.C) {
			actual, err := idputil.ReadGroupsFromCSV(test.groups)
			c.Assert(err, qt.IsNil)
			c.Check(actual, qt.CmpEquals(cmpopts.EquateEmpty()), test.expect)
		})
	}
}
