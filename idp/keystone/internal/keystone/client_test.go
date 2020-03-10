// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keystone_test

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/candid/idp/keystone/internal/keystone"
)

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

func TestUnmarshalError(t *testing.T) {
	c := qt.New(t)
	for _, test := range unmarshalErrorTests {
		c.Run(test.about, func(c *qt.C) {
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
				c.Assert(err, qt.DeepEquals, test.expect)
			}
			c.Assert(err, qt.ErrorMatches, test.expectError)
		})
	}
}
