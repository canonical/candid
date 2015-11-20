// Copyright 2015 Canonical Ltd.

package idp_test

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/juju/httprequest"
	"github.com/juju/testing"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon.v1"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity/internal/idp"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

type idpSuite struct {
	testing.IsolatedMgoSuite
	pool  *store.Pool
	store *store.Store
}

func (s *idpSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error

	s.pool, err = store.NewPool(s.Session.DB("testing"), store.StoreParams{
		Launchpad:   lpad.Production,
		PrivateAddr: "localhost",
	})
	c.Assert(err, gc.IsNil)
	s.store = s.pool.GetNoLimit()
}

func (s *idpSuite) TearDownTest(c *gc.C) {
	s.store.Close()
	s.pool.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

// testContext is an idpContext that can be used in tests.
type testContext struct {
	store      *store.Store
	requestURL string
	params     httprequest.Params
	macaroon   macaroon.Slice
	success    bool
	err        error
}

func (t *testContext) Store() *store.Store {
	return t.store
}

func (t *testContext) IDPURL(path string) string {
	return "https://idp.test" + path
}

func (t *testContext) RequestURL() string {
	return t.requestURL
}

func (t *testContext) LoginSuccess(ms macaroon.Slice) bool {
	t.macaroon = ms
	return t.success
}

func (t *testContext) LoginFailure(err error) {
	t.err = err
}

func (t *testContext) Params() httprequest.Params {
	return t.params
}

var _ idp.Context = &testContext{}

func body(v interface{}) io.ReadCloser {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return ioutil.NopCloser(bytes.NewReader(data))
}
