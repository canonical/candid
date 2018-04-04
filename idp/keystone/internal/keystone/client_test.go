// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone_test

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/idp/keystone/internal/keystone"
)

type clientSuite struct{}

var _ = gc.Suite(&clientSuite{})

var unmarshalErrorTests = []struct {
	about       string
	body        string
	expect      *keystone.Error
	expectError string
}{{
	about: "error",
	body:  `{"error":{"code":400, "message":"test error","title":"Test"}}`,
	expect: &keystone.Error{
		Code:    400,
		Message: "test error",
		Title:   "Test",
	},
	expectError: "test error",
}, {
	about:       "bad json",
	body:        `{"error":{"code":400, "message":"test error","title":"Test"}`,
	expectError: "unexpected end of JSON input",
}}

func (s *clientSuite) TestUnmarshalError(c *gc.C) {
	for i, test := range unmarshalErrorTests {
		c.Logf("%d. %s", i, test.about)
		resp := &http.Response{
			Body: ioutil.NopCloser(strings.NewReader(test.body)),
			Header: http.Header{
				"Content-Type": {"application/json"},
			},
			Request: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Scheme: "http",
					Host:   "example.com",
					Path:   "test",
				},
			},
		}
		err := keystone.UnmarshalError(resp)
		if test.expect != nil {
			c.Assert(err, jc.DeepEquals, test.expect)
		}
		c.Assert(err, gc.ErrorMatches, test.expectError)
	}
}
