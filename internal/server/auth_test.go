// Copyright 2014 Canonical Ltd.

package server

import (
	"net/http"

	gc "gopkg.in/check.v1"
)

type authSuite struct{}

var _ = gc.Suite(&authSuite{})

func (s *authSuite) TestHasAdminCredentials(c *gc.C) {
	auth := NewAuthorizer(
		ServerParams{
			"test-admin",
			"open sesame",
		},
	)
	tests := []struct {
		about              string
		header             http.Header
		expectErrorMessage string
	}{{
		about: "good credentials",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1hZG1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expectErrorMessage: "",
	}, {
		about: "bad username",
		header: http.Header{
			"Authorization": []string{"Basic eGVzdC1hZG1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expectErrorMessage: "invalid credentials",
	}, {
		about: "bad password",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1hZG1pbjpvcGVuIHNlc2FtAQ=="},
		},
		expectErrorMessage: "invalid credentials",
	}, {
		about: "incorrect type",
		header: http.Header{
			"Authorization": []string{"Digest dGVzdC1hZG1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expectErrorMessage: "unauthorized: invalid or missing HTTP auth header",
	}, {
		about: "empty authorization",
		header: http.Header{
			"Authorization": []string{""},
		},
		expectErrorMessage: "unauthorized: invalid or missing HTTP auth header",
	}, {
		about:              "no authorization",
		header:             http.Header{},
		expectErrorMessage: "unauthorized: invalid or missing HTTP auth header",
	}, {
		about: "invalid base64",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1h<>1pbjpvcGVuIHNlc2FtZQ=="},
		},
		expectErrorMessage: "unauthorized: invalid HTTP auth encoding",
	}, {
		about: "no colon",
		header: http.Header{
			"Authorization": []string{"Basic dGVzdC1hZG1pbg=="},
		},
		expectErrorMessage: "unauthorized: invalid HTTP auth contents",
	}}
	for i, test := range tests {
		c.Logf("%d. %s", i, test.about)
		obtained := auth.HasAdminCredentials(&http.Request{
			Header: test.header,
		})
		if test.expectErrorMessage == "" {
			c.Assert(obtained, gc.Equals, nil)
		} else {
			c.Assert(obtained.Error(), gc.Equals, test.expectErrorMessage)
		}
	}
}
