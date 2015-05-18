// Copyright 2014 Canonical Ltd.

package v1_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"launchpad.net/lpad"

	"github.com/juju/testing/httptesting"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/mgostorage"
	"gopkg.in/macaroon.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/idtesting"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/server"
	"github.com/CanonicalLtd/blues-identity/internal/store"
	"github.com/CanonicalLtd/blues-identity/internal/v1"
	"github.com/CanonicalLtd/blues-identity/params"
)

const (
	version       = "v1"
	adminUsername = "admin"
	adminPassword = "password"
	location      = "https://0.1.2.3/identity"
)

type apiSuite struct {
	idtesting.IsolatedMgoSuite
	srv     http.Handler
	store   *store.Store
	keyPair *bakery.KeyPair
	svc     *bakery.Service
}

var _ = gc.Suite(&apiSuite{})

func (s *apiSuite) SetUpSuite(c *gc.C) {
	s.IsolatedMgoSuite.SetUpSuite(c)
}

func (s *apiSuite) TearDownSuite(c *gc.C) {
	s.IsolatedMgoSuite.TearDownSuite(c)
}

func (s *apiSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)

	key, err := bakery.GenerateKey()
	c.Assert(err, gc.IsNil)
	s.srv, s.store = newServer(c, s.Session, key)
	// Create Macaroon storage.
	ms, err := mgostorage.New(s.store.DB.Macaroons())
	c.Assert(err, gc.IsNil)
	// Create the bakery Service.
	svc, err := bakery.NewService(bakery.NewServiceParams{
		Store: ms,
		Key:   key,
	})
	c.Assert(err, gc.IsNil)
	s.svc = svc
	s.keyPair = key
}

func fakeRedirectURL(_, _, _ string) (string, error) {
	return "http://0.1.2.3/nowhere", nil
}

func (s *apiSuite) TearDownTest(c *gc.C) {
	s.IsolatedMgoSuite.TearDownTest(c)
}

func newServer(c *gc.C, session *mgo.Session, key *bakery.KeyPair) (http.Handler, *store.Store) {
	db := session.DB("testing")
	st, err := store.New(db, lpad.Staging)
	c.Assert(err, gc.IsNil)
	srv, err := server.New(
		db,
		server.ServerParams{
			AuthUsername: adminUsername,
			AuthPassword: adminPassword,
			Key:          key,
			Location:     location,
		},
		map[string]server.NewAPIHandlerFunc{
			version: v1.NewAPIHandler,
		},
	)
	c.Assert(err, gc.IsNil)
	return srv, st
}

func (s *apiSuite) assertMacaroon(c *gc.C, ms macaroon.Slice, check bakery.FirstPartyChecker) {
	err := s.svc.Check(ms, check)
	c.Assert(err, gc.IsNil)
}

func (s *apiSuite) createUser(c *gc.C, user *params.User) (uuid string) {
	c.Logf("DefaultClient: %#v, DefaultTransport: %#v", http.DefaultClient, http.DefaultTransport)
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: s.srv,
		URL:     apiURL("u/" + string(user.Username)),
		Method:  "PUT",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:         marshal(c, user),
		Username:     adminUsername,
		Password:     adminPassword,
		ExpectStatus: http.StatusOK,
	})

	// Retrieve and return the newly created user's UUID.
	var id mongodoc.Identity
	err := s.store.DB.Identities().Find(
		bson.D{{"username", user.Username}},
	).Select(bson.D{{"baseurl", 1}}).One(&id)
	c.Assert(err, gc.IsNil)
	return id.UUID
}

func apiURL(path string) string {
	return "/" + version + "/" + path
}

// transport implements an http.RoundTripper that will intercept anly calls
// destined to a location starting with prefix and serves them using srv. For
// all other requests rt will be used.
type transport struct {
	prefix string
	srv    http.Handler
	rt     http.RoundTripper
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	dest := req.URL.String()
	if !strings.HasPrefix(dest, t.prefix) {
		return t.rt.RoundTrip(req)
	}
	var buf bytes.Buffer
	req.Write(&buf)
	sreq, _ := http.ReadRequest(bufio.NewReader(&buf))
	u, _ := url.Parse(t.prefix)
	sreq.URL.Path = strings.TrimPrefix(sreq.URL.Path, u.Path)
	sreq.RequestURI = strings.TrimPrefix(sreq.RequestURI, u.Path)
	sreq.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	t.srv.ServeHTTP(rr, sreq)
	return &http.Response{
		Status:        fmt.Sprintf("%d Status", rr.Code),
		StatusCode:    rr.Code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        rr.HeaderMap,
		Body:          ioutil.NopCloser(rr.Body),
		ContentLength: int64(rr.Body.Len()),
		Request:       req,
	}, nil
}
