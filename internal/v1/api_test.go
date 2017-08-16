// Copyright 2014 Canonical Ltd.

package v1_test

import (
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/discharger"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/idmtest"
	"github.com/CanonicalLtd/blues-identity/internal/v1"
)

var versions = map[string]identity.NewAPIHandlerFunc{
	"discharger": discharger.NewAPIHandler,
	"v1":         v1.NewAPIHandler,
}

type apiSuite struct {
	idmtest.StoreServerSuite
}

func (s *apiSuite) SetUpTest(c *gc.C) {
	s.Versions = versions
	s.StoreServerSuite.SetUpTest(c)
}

//const (
//	version       = "v1"
//	adminUsername = "admin"
//	adminPassword = "password"
//	location      = "https://0.1.2.3/identity"
//)
//
//type apiSuite struct {
//	testing.IsolatedMgoSuite
//	srv      *identity.Server
//	pool     *store.Pool
//	keyPair  *bakery.KeyPair
//	idps     []idp.IdentityProvider
//	server   *httptest.Server
//	template *template.Template
//	bakery   *bakery.Bakery
//}
//
//var _ = gc.Suite(&apiSuite{})
//
//func (s *apiSuite) SetUpSuite(c *gc.C) {
//	s.IsolatedMgoSuite.SetUpSuite(c)
//}
//
//func (s *apiSuite) TearDownSuite(c *gc.C) {
//	s.IsolatedMgoSuite.TearDownSuite(c)
//}
//
//func (s *apiSuite) SetUpTest(c *gc.C) {
//	s.IsolatedMgoSuite.SetUpTest(c)
//
//	key, err := bakery.GenerateKey()
//	c.Assert(err, gc.IsNil)
//	rks := bakery.NewMemRootKeyStore()
//	s.bakery = bakery.New(bakery.BakeryParams{
//		RootKeyStore:   rks,
//		IdentityClient: testIdentityClient{},
//		Key:            key,
//	})
//	s.template = template.New("")
//	s.srv, s.pool = newServer(c, s.Session.Copy(), rks, s.template, s.idps)
//	s.keyPair = key
//	s.server = httptest.NewServer(s.srv)
//	s.PatchValue(&http.DefaultTransport, httptesting.URLRewritingTransport{
//		MatchPrefix:  location,
//		Replace:      s.server.URL,
//		RoundTripper: http.DefaultTransport,
//	})
//}
//
//func (s *apiSuite) TearDownTest(c *gc.C) {
//	s.srv.Close()
//	s.pool.Close()
//	s.IsolatedMgoSuite.TearDownTest(c)
//}
//
//func fakeRedirectURL(_, _, _ string) (string, error) {
//	return "http://0.1.2.3/nowhere", nil
//}
//
//func newServer(c *gc.C, session *mgo.Session, rks bakery.RootKeyStore, t *template.Template, idps []idp.IdentityProvider) (*identity.Server, *store.Pool) {
//	db := session.DB("testing")
//	sp := identity.ServerParams{
//		RootKeyStore:      rks,
//		AuthUsername:      adminUsername,
//		AuthPassword:      adminPassword,
//		Location:          location,
//		MaxMgoSessions:    50,
//		IdentityProviders: idps,
//		PrivateAddr:       "localhost",
//		Template:          t,
//	}
//	pool, err := store.NewPool(db, store.StoreParams{
//		MaxMgoSessions: sp.MaxMgoSessions,
//	})
//	c.Assert(err, gc.IsNil)
//	srv, err := identity.New(
//		db,
//		sp,
//		map[string]identity.NewAPIHandlerFunc{
//			version: v1.NewAPIHandler,
//		},
//	)
//	c.Assert(err, gc.IsNil)
//	return srv, pool
//}
//
//func (s *apiSuite) assertMacaroon(c *gc.C, ms macaroon.Slice, expectUser string) {
//	authInfo, err := s.bakery.Checker.Auth(ms).Allow(context.TODO(), bakery.LoginOp)
//	c.Assert(err, gc.IsNil)
//	c.Assert(authInfo.Identity, gc.NotNil)
//	c.Assert(authInfo.Identity.Id(), gc.Equals, expectUser)
//}
//
//func (s *apiSuite) createUser(c *gc.C, user *params.User) {
//	store := s.pool.GetNoLimit()
//	defer s.pool.Put(store)
//	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
//		Handler: s.srv,
//		URL:     apiURL("u/" + string(user.Username)),
//		Method:  "PUT",
//		Header: http.Header{
//			"Content-Type": []string{"application/json"},
//		},
//		Body:         marshal(c, user),
//		Username:     adminUsername,
//		Password:     adminPassword,
//		ExpectStatus: http.StatusOK,
//	})
//
//	// Retrieve and return the newly created user's UUID.
//	var id mongodoc.Identity
//	err := store.DB.Identities().Find(
//		bson.D{{"username", user.Username}},
//	).Select(bson.D{{"baseurl", 1}}).One(&id)
//	c.Assert(err, gc.IsNil)
//}
//
//func (s *apiSuite) createIdentity(c *gc.C, doc *mongodoc.Identity) {
//	store := s.pool.GetNoLimit()
//	defer s.pool.Put(store)
//	if doc.Owner != "" {
//		err := store.UpsertAgent(doc)
//		c.Assert(err, gc.IsNil)
//	} else {
//		err := store.UpsertUser(doc)
//		c.Assert(err, gc.IsNil)
//	}
//}
//
//func apiURL(path string) string {
//	return location + "/" + version + "/" + path
//}
//
//var DischargeRequiredBody httptesting.BodyAsserter = func(c *gc.C, body json.RawMessage) {
//	var e httpbakery.Error
//	err := json.Unmarshal(body, &e)
//	c.Assert(err, gc.IsNil)
//	c.Assert(e.Code, gc.Equals, httpbakery.ErrDischargeRequired)
//}
//
//// marshal converts a value into a bytes.Reader containing the json
//// encoding of that value.
//func marshal(c *gc.C, v interface{}) *bytes.Reader {
//	b, err := json.Marshal(v)
//	c.Assert(err, gc.Equals, nil)
//	return bytes.NewReader(b)
//}
//
//type testIdentityClient struct{}
//
//func (testIdentityClient) IdentityFromContext(context.Context) (bakery.Identity, []checkers.Caveat, error) {
//	return nil, nil, nil
//}
//
//func (testIdentityClient) DeclaredIdentity(_ context.Context, declared map[string]string) (bakery.Identity, error) {
//	if name, ok := declared["username"]; ok {
//		return bakery.SimpleIdentity(name), nil
//	}
//	return nil, errgo.New("no username declared")
//}
