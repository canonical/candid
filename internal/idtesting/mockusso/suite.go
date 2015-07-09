// Copyright 2015 Canonical Ltd.

package mockusso

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

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
	rt := roundTripper{
		c:   c,
		rt:  http.DefaultTransport,
		url: s.server.URL,
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

// roundTripper implements http.RoundTripper by
// wrapping rt and rewriting any requests addressed to
// https://login.ubuntu.com/ to use url instead.
// It uses c to log the requests.
type roundTripper struct {
	c   *gc.C
	rt  http.RoundTripper
	url string
}

func (rt roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	dest := req.URL.String()
	req1 := *req
	if strings.HasPrefix(dest, "https://login.ubuntu.com/") {
		rt.c.Logf("intercepting request to %s", req.URL)
		dest = rt.url + strings.TrimPrefix(dest, "https://login.ubuntu.com")
		var err error

		req1.URL, err = url.Parse(dest)
		if err != nil {
			panic(err)
		}
	}
	resp, err := rt.rt.RoundTrip(&req1)
	if resp != nil {
		resp.Request = req
	}
	return resp, err
}
