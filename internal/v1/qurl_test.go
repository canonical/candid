package v1

import (
	"net/url"

	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
)

type qURLSuite struct{}

var _ = gc.Suite(&qURLSuite{})

var qURLParseTests = []struct {
	url    string
	expect *qURL
}{{
	url: "http://foo.bar/baz",
	expect: &qURL{
		URL: &url.URL{
			Scheme: "http",
			Host:   "foo.bar",
			Path:   "/baz",
		},
		Query: url.Values{},
	},
}, {
	url: "http://foo.bar/baz?attr1=val1.1&attr1=val1.2&attr2=val2",
	expect: &qURL{
		URL: &url.URL{
			Scheme: "http",
			Host:   "foo.bar",
			Path:   "/baz",
		},
		Query: url.Values{
			"attr1": {"val1.1", "val1.2"},
			"attr2": {"val2"},
		},
	},
}}

func (*qURLSuite) TestQURLParse(c *gc.C) {
	for i, test := range qURLParseTests {
		c.Logf("test %d", i)
		qu, err := parseQURL(test.url)
		c.Assert(err, gc.IsNil)
		c.Assert(qu.String(), gc.Equals, test.url)
		c.Assert(qu, jc.DeepEquals, test.expect)
	}
}
