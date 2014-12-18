// Copyright 2014 Canonical Ltd.

package server

import (
	"net/http"

	gc "gopkg.in/check.v1"
)

type authSuite struct{}

var _ = gc.Suite(&authSuite{})

func (s *authSuite) TestHasAdminCredentials(c *gc.C) {
	auth := NewAuthorization(
		ServerParams{
			"test-admin",
			"open sesame",
		},
	)
	tests := []struct {
		about    string
		header   http.Header
		expected bool
	}{{
		about: "good credentials",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1hZG1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expected: true,
	}, {
		about: "bad username",
		header: http.Header{
			"Authorization": []string{"Basic eGVzdC1hZG1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expected: false,
	}, {
		about: "bad password",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1hZG1pbjpvcGVuIHNlc2FtAQ=="},
		},
		expected: false,
	}, {
		about: "incorrect type",
		header: http.Header{
			"Authorization": []string{"Digest dGVzdC1hZG1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expected: false,
	}, {
		about: "empty authorization",
		header: http.Header{
			"Authorization": []string{""},
		},
		expected: false,
	}, {
		about:    "no authorization",
		header:   http.Header{},
		expected: false,
	}, {
		about: "invalid base64",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1h<>1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expected: false,
	}, {
		about: "no colon",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1hZG1pbg=="},
		},
		expected: false,
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		obtained := auth.HasAdminCredentials(&http.Request{
			Header: test.header,
		})
		c.Assert(obtained, gc.Equals, test.expected)
	}
}
