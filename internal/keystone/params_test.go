// Copyright 2015 Canonical Ltd.

package keystone_test

import (
	"time"

	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/keystone"
)

type paramsSuite struct{}

var _ = gc.Suite(&paramsSuite{})

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

func (s *paramsSuite) TestTimeUnmarshalJSON(c *gc.C) {
	for i, test := range timeUnmarshalJSONTests {
		var t keystone.Time
		c.Logf("%d. %q", i, test.json)
		err := t.UnmarshalJSON([]byte(test.json))
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			continue
		}
		c.Assert(err, gc.IsNil)
		c.Assert(t.Equal(test.expect), gc.Equals, true, gc.Commentf("obtained: %#v, expected: %#v", t, test.expect))
	}
}
