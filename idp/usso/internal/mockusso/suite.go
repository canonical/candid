// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mockusso

import (
	"net/http"
	"net/http/httptest"

	"github.com/juju/qthttptest"
)

// Server represents a mock USSO server.
type Server struct {
	MockUSSO *Handler
	server   *httptest.Server
	saved    http.RoundTripper
}

// NewServer starts a mock USSO server and also modifies
// http.DefaultTransport to redirect requests addressed to
// https://login.ubuntu.com to it.
//
// The returned Server must be closed after use.
func NewServer() *Server {
	s := &Server{
		MockUSSO: New("https://login.ubuntu.com"),
	}
	s.server = httptest.NewServer(s.MockUSSO)
	rt := qthttptest.URLRewritingTransport{
		MatchPrefix:  "https://login.ubuntu.com",
		Replace:      s.server.URL,
		RoundTripper: http.DefaultTransport,
	}
	s.saved = http.DefaultTransport
	http.DefaultTransport = rt
	return s
}

func (s *Server) Close() {
	http.DefaultTransport = s.saved
	s.server.Close()
}
