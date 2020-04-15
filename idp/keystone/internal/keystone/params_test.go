// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone_test

import (
	"fmt"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/candid/idp/keystone/internal/keystone"
)

var timeUnmarshalJSONTests = []struct {
	json        string
	expect      time.Time
	expectError string
}{{
	json:   `"2015-09-21T10:38:15.788236"`,
	expect: time.Date(2015, 9, 21, 10, 38, 15, 788236000, time.UTC),
}, {
	json:   `"2015-09-22T10:38:15Z"`,
	expect: time.Date(2015, 9, 22, 10, 38, 15, 0, time.UTC),
}, {
	json:        `"yesterday"`,
	expectError: `parsing time ""yesterday"" as ""2006-01-02T15:04:05"": cannot parse "yesterday"" as "2006"`,
}}

func TestTimeUnmarshalJSON(t *testing.T) {
	c := qt.New(t)
	for i, test := range timeUnmarshalJSONTests {
		c.Run(fmt.Sprintf("test%d", i), func(c *qt.C) {
			var t keystone.Time
			err := t.UnmarshalJSON([]byte(test.json))
			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				return
			}
			c.Assert(err, qt.IsNil)
			c.Assert(t.Equal(test.expect), qt.Equals, true, qt.Commentf("obtained: %#v, expected: %#v", t, test.expect))
		})
	}
}
