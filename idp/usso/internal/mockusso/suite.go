// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mockusso

import (
	"net/http"
	"net/http/httptest"

	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
)

type Suite struct {
	MockUSSO *Handler
	server   *httptest.Server
	saved    http.RoundTripper
}

func (s *Suite) SetUpSuite(c *gc.C) {
	s.MockUSSO = New("https://login.ubuntu.com")
	s.server = httptest.NewServer(s.MockUSSO)
	rt := httptesting.URLRewritingTransport{
		MatchPrefix:  "https://login.ubuntu.com",
		Replace:      s.server.URL,
		RoundTripper: http.DefaultTransport,
	}
	s.saved = http.DefaultTransport
	http.DefaultTransport = rt
}

func (s *Suite) TearDownSuite(c *gc.C) {
	http.DefaultTransport = s.saved
	s.server.Close()
}

func (s *Suite) SetUpTest(c *gc.C) {
}

func (s *Suite) TearDownTest(c *gc.C) {
	s.MockUSSO.Reset()
}
