// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package openid_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"gopkg.in/yaml.v2"

	"github.com/canonical/candid/config"
	idppkg "github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/idptest"
	"github.com/canonical/candid/idp/idputil"
	"github.com/canonical/candid/idp/openid"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/store"
)

var configTests = []struct {
	name        string
	yaml        string
	expectError string
}{{
	name: "OK",
	yaml: `
identity-providers:
- type: openid-connect
  name: test
  issuer: example.com
  client-id: test-client-id
  client-secret: test-client-secret
`[1:],
}, {
	name: "NoName",
	yaml: `
identity-providers:
- type: openid-connect
  issuer: example.com
  client-id: test-client-id
  client-secret: test-client-secret
`[1:],
	expectError: "cannot unmarshal openid-connect configuration: name not specified",
}, {
	name: "NoIssuer",
	yaml: `
identity-providers:
- type: openid-connect
  name: test
  client-id: test-client-id
  client-secret: test-client-secret
`[1:],
	expectError: "cannot unmarshal openid-connect configuration: issuer not specified",
}, {
	name: "NoClientID",
	yaml: `
identity-providers:
- type: openid-connect
  name: test
  issuer: example.com
  client-secret: test-client-secret
`[1:],
	expectError: "cannot unmarshal openid-connect configuration: client-id not specified",
}, {
	name: "NoClientSecret",
	yaml: `
identity-providers:
- type: openid-connect
  name: test
  issuer: example.com
  client-id: test-client-id
`[1:],
	expectError: "cannot unmarshal openid-connect configuration: client-secret not specified",
}}

func TestConfig(t *testing.T) {
	c := qt.New(t)
	for _, test := range configTests {
		c.Run(test.name, func(c *qt.C) {
			var conf config.Config
			err := yaml.Unmarshal([]byte(test.yaml), &conf)
			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				return
			}
			c.Assert(err, qt.IsNil)
			c.Assert(conf.IdentityProviders, qt.HasLen, 1)
			c.Assert(conf.IdentityProviders[0].Name(), qt.Equals, "test")
		})
	}
}

func TestName(t *testing.T) {
	c := qt.New(t)

	idp := openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Name: "abcdef",
	})

	c.Check(idp.Name(), qt.Equals, "abcdef")
}

func TestDomain(t *testing.T) {
	c := qt.New(t)

	idp := openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Name:   "abcdef",
		Domain: "ghijklmn",
	})

	c.Check(idp.Domain(), qt.Equals, "ghijklmn")
}

func TestDescription(t *testing.T) {
	c := qt.New(t)

	idp := openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Description: "test openid-connect idp",
	})

	c.Check(idp.Description(), qt.Equals, "test openid-connect idp")
}

func TestInteractive(t *testing.T) {
	c := qt.New(t)

	idp := openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{})
	c.Check(idp.Interactive(), qt.Equals, true)
}

func TestHidden(t *testing.T) {
	c := qt.New(t)

	idp := openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Hidden: true,
	})
	c.Check(idp.Hidden(), qt.Equals, true)
}

func TestIsForEmailAddr(t *testing.T) {
	c := qt.New(t)

	idp := openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{})
	type ifea interface {
		IsForEmailAddr(string) bool
	}
	c.Check(idp.(ifea).IsForEmailAddr("me@example.com"), qt.Equals, false)

	idp = openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		MatchEmailAddr: "@example.com$",
	})

	c.Check(idp.(ifea).IsForEmailAddr("me@example.com"), qt.Equals, true)
	c.Check(idp.(ifea).IsForEmailAddr("me@example.net"), qt.Equals, false)
	c.Check(idp.(ifea).IsForEmailAddr("me@example.com.zz"), qt.Equals, false)
}

func TestURL(t *testing.T) {
	c := qt.New(t)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	idp := openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Issuer: srv.URL,
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		conf := map[string]string{
			"issuer": srv.URL,
		}
		e := json.NewEncoder(w)
		if err := e.Encode(conf); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	err := idp.Init(context.Background(), idppkg.InitParams{
		URLPrefix: "https://example.com/login/oidc",
	})
	c.Assert(err, qt.IsNil)
	c.Check(idp.URL("1234"), qt.Equals, "https://example.com/login/oidc/login?state=1234")
}

func TestIconURL(t *testing.T) {
	c := qt.New(t)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	idp := openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Issuer: srv.URL,
		Icon:   "static/oidc.ico",
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		conf := map[string]string{
			"issuer": srv.URL,
		}
		e := json.NewEncoder(w)
		if err := e.Encode(conf); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	err := idp.Init(context.Background(), idppkg.InitParams{
		Location: "https://example.com",
	})
	c.Assert(err, qt.IsNil)
	c.Check(idp.IconURL(), qt.Equals, "https://example.com/static/oidc.ico")
}

func TestHandleLogin(t *testing.T) {
	c := qt.New(t)

	srv := newTestOIDCServer()
	defer srv.Close()

	idp := openid.NewOpenIDConnectIdentityProvider(openid.OpenIDConnectParams{
		Issuer:   srv.URL,
		ClientID: "test-client-id",
		Scopes:   []string{"openid", "email"},
	})

	f := idptest.NewFixture(c, candidtest.NewStore())

	ip := f.InitParams(c, "http://example.com/login/oidc")
	err := idp.Init(context.Background(), ip)
	c.Assert(err, qt.IsNil)

	cl := idptest.NewClient(idp, ip.Codec)
	cl.SetLoginState(idputil.LoginState{
		ReturnTo: "http://example.com/callback",
		State:    "1234",
		Expires:  time.Now().Add(10 * time.Minute),
	})

	resp, err := cl.Get("/login")
	c.Assert(err, qt.IsNil)
	c.Check(resp.StatusCode, qt.Equals, http.StatusFound, qt.Commentf(resp.Status))
	u, err := url.Parse(resp.Header.Get("Location"))
	c.Assert(err, qt.IsNil)
	c.Check(u.Scheme+"://"+u.Host+u.Path, qt.Equals, srv.URL+"/auth")
	vs := u.Query()
	c.Check(vs.Get("state"), qt.Not(qt.Equals), "")
	c.Check(vs.Get("client_id"), qt.Equals, "test-client-id")
	c.Check(vs.Get("redirect_uri"), qt.Equals, "http://example.com/login/oidc/callback")
	c.Check(vs.Get("scope"), qt.Equals, "openid email")
}

var handleCallbackTests = []struct {
	name             string
	storedIdentities func(string) []store.Identity
	claims           map[string]interface{}
	expectIdentity   func(string) store.Identity
}{{
	name: "NewUserWithUsername",
	claims: map[string]interface{}{
		"sub":                "user-id-1",
		"preferred_username": "user1",
		"email":              "user1@example.com",
		"name":               "User One",
	},
	expectIdentity: func(s string) store.Identity {
		return store.Identity{
			ProviderID: store.ProviderIdentity("oidc:" + s + ":user-id-1"),
			Username:   "user1",
			Email:      "user1@example.com",
			Name:       "User One",
		}
	},
}, {
	name: "NewUserNoUsername",
	claims: map[string]interface{}{
		"sub":   "user-id-1",
		"email": "user1@example.com",
		"name":  "User One",
	},
}, {
	name: "ExistingUserNoClaims",
	storedIdentities: func(s string) []store.Identity {
		return []store.Identity{{
			ProviderID: store.ProviderIdentity("oidc:" + s + ":user-id-1"),
			Username:   "user1",
			Email:      "user1@example.com",
			Name:       "User One",
		}}
	},
	claims: map[string]interface{}{
		"sub": "user-id-1",
	},
	expectIdentity: func(s string) store.Identity {
		return store.Identity{
			ProviderID: store.ProviderIdentity("oidc:" + s + ":user-id-1"),
			Username:   "user1",
			Email:      "user1@example.com",
			Name:       "User One",
		}
	},
}, {
	name: "ExistingUserUpdateClaims",
	storedIdentities: func(s string) []store.Identity {
		return []store.Identity{{
			ProviderID: store.ProviderIdentity("oidc:" + s + ":user-id-1"),
			Username:   "user1",
			Email:      "user1@example.com",
			Name:       "User One",
		}}
	},
	claims: map[string]interface{}{
		"sub":                "user-id-1",
		"preferred_username": "user0",
		"email":              "user0@example.com",
		"name":               "User Zero",
		"groups":             []string{"group1", "group2"},
	},
	expectIdentity: func(s string) store.Identity {
		return store.Identity{
			ProviderID: store.ProviderIdentity("oidc:" + s + ":user-id-1"),
			Username:   "user1",
			Email:      "user0@example.com",
			Name:       "User Zero",
			Groups:     []string{"group1", "group2"},
		}
	},
}, {
	name: "PreferredUsernameTaken",
	storedIdentities: func(s string) []store.Identity {
		return []store.Identity{{
			ProviderID: store.ProviderIdentity("oidc:" + s + ":user-id-1"),
			Username:   "user1",
			Email:      "user1@example.com",
			Name:       "User One",
		}}
	},
	claims: map[string]interface{}{
		"sub":                "user-id-2",
		"preferred_username": "user1",
		"email":              "user1@example.com",
		"name":               "User One",
	},
}}

func TestHandleCallback(t *testing.T) {
	c := qt.New(t)

	for _, test := range handleCallbackTests {
		c.Run(test.name, func(c *qt.C) {
			srv := newTestOIDCServer()
			defer srv.Close()

			p := openid.OpenIDConnectParams{
				Name:   "oidc",
				Issuer: srv.URL,
			}
			p.ClientID, p.ClientSecret = srv.clientCreds()
			idp := openid.NewOpenIDConnectIdentityProvider(p)
			st := candidtest.NewStore()
			f := idptest.NewFixture(c, st)

			ip := f.InitParams(c, "http://example.com/login/oidc")
			ip.Template = template.New("")
			template.Must(ip.Template.New("register").Parse("{{.State}}\n{{.Error}}"))
			err := idp.Init(context.Background(), ip)
			c.Assert(err, qt.IsNil)

			if test.storedIdentities != nil {
				for _, id := range test.storedIdentities(srv.URL) {
					err := st.Store.UpdateIdentity(context.Background(), &id, store.Update{
						store.Username: store.Set,
						store.Email:    store.Set,
						store.Name:     store.Set,
						store.Groups:   store.Set,
					})
					c.Assert(err, qt.IsNil)
				}
			}

			cl := idptest.NewClient(idp, ip.Codec)
			cl.SetLoginState(idputil.LoginState{
				ReturnTo: "http://example.com/callback",
				State:    "1234",
				Expires:  time.Now().Add(10 * time.Minute),
			})
			srv.setClaim("aud", p.ClientID)
			srv.setClaim("exp", time.Now().Add(time.Minute).Unix())
			srv.setClaim("iat", time.Now().Unix())
			for k, v := range test.claims {
				srv.setClaim(k, v)
			}
			resp, err := cl.Get("/callback?code=" + srv.code())
			c.Assert(err, qt.IsNil)
			id, err := f.ParseResponse(c, resp)
			c.Assert(err, qt.IsNil)
			if test.expectIdentity == nil {
				c.Check(id, qt.IsNil)
			} else {
				id.ID = ""
				expectID := test.expectIdentity(srv.URL)
				c.Check(id, qt.CmpEquals(cmpopts.EquateEmpty()), &expectID)
			}
		})
	}
}

var handleRegisterTests = []struct {
	name             string
	storedIdentities []store.Identity
	username         string
	fullname         string
	email            string
	groups           []string
	expectIdentity   store.Identity
	expectError      string
}{{
	name:     "Success",
	username: "user1",
	fullname: "User One",
	email:    "user1@example.com",
	groups:   []string{"group1", "group2"},
	expectIdentity: store.Identity{
		ProviderID: "oidc:example.com:user-id-1",
		Username:   "user1@test",
		Name:       "User One",
		Email:      "user1@example.com",
		Groups:     []string{"group1", "group2"},
	},
}, {
	name:        "InvalidUsername",
	username:    "!",
	fullname:    "User One",
	email:       "user1@example.com",
	expectError: "invalid user name. The username must contain only A-Z, a-z, 0-9, &#39;.&#39;, &#39;-&#39;, &amp; &#39;&#43;&#39;, and must start and end with a letter or number.",
}, {
	name: "InvalidUsername",
	storedIdentities: []store.Identity{{
		ProviderID: "oidc:example.com:user-id-0",
		Username:   "user1@test",
	}},
	username:    "user1",
	fullname:    "User One",
	email:       "user1@example.com",
	expectError: "Username already taken, please pick a different one.",
}}

func TestHandleRegister(t *testing.T) {
	c := qt.New(t)

	for _, test := range handleRegisterTests {
		c.Run(test.name, func(c *qt.C) {
			srv := newTestOIDCServer()
			defer srv.Close()
			p := openid.OpenIDConnectParams{
				Name:   "oidc",
				Domain: "test",
				Issuer: srv.URL,
			}
			idp := openid.NewOpenIDConnectIdentityProvider(p)
			st := candidtest.NewStore()
			f := idptest.NewFixture(c, st)
			ip := f.InitParams(c, "http://example.com/login/oidc")
			ip.Template = template.New("")
			template.Must(ip.Template.New("register").Parse("{{.State}}\n{{.Error}}"))
			err := idp.Init(context.Background(), ip)
			c.Assert(err, qt.IsNil)

			for _, id := range test.storedIdentities {
				err := st.Store.UpdateIdentity(context.Background(), &id, store.Update{
					store.Username: store.Set,
					store.Email:    store.Set,
					store.Name:     store.Set,
					store.Groups:   store.Set,
				})
				c.Assert(err, qt.IsNil)
			}

			cl := idptest.NewClient(idp, ip.Codec)
			cl.SetLoginState(idputil.LoginState{
				ProviderID: "oidc:example.com:user-id-1",
				ReturnTo:   "http://example.com/callback",
				State:      "1234",
				Expires:    time.Now().Add(10 * time.Minute),
			})
			vs := make(url.Values)
			if test.username != "" {
				vs.Set("username", test.username)
			}
			if test.fullname != "" {
				vs.Set("fullname", test.fullname)
			}
			if test.email != "" {
				vs.Set("email", test.email)
			}
			if test.groups != nil {
				data, err := json.Marshal(test.groups)
				c.Assert(err, qt.IsNil)
				vs.Set("groups", string(data))
			}
			req, err := http.NewRequest("POST", "/register", strings.NewReader(vs.Encode()))
			c.Assert(err, qt.IsNil)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := cl.Do(req)
			c.Assert(err, qt.IsNil)
			id, err := f.ParseResponse(c, resp)
			if test.expectError != "" {
				c.Check(err, qt.ErrorMatches, test.expectError)
				return
			}
			if test.expectIdentity.ProviderID != "" {
				c.Check(err, qt.IsNil)
				id.ID = ""
				c.Check(id, qt.CmpEquals(cmpopts.EquateEmpty()), &test.expectIdentity)
			}
		})
	}
}

type testOIDCServer struct {
	*httptest.Server

	mu                     sync.Mutex
	clientID, clientSecret string
	claims_                map[string]interface{}
	code_                  string
	key_                   *rsa.PrivateKey
}

func newTestOIDCServer() *testOIDCServer {
	var srv testOIDCServer
	srv.Server = httptest.NewServer(&srv)
	return &srv
}

func (s *testOIDCServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	switch req.URL.Path {
	case "/.well-known/openid-configuration":
		s.serveConfiguration(w, req)
	case "/token":
		s.serveToken(w, req)
	case "/keys":
		s.serveKeys(w, req)
	default:
		http.NotFound(w, req)
	}
}

func (s *testOIDCServer) serveConfiguration(w http.ResponseWriter, req *http.Request) {
	conf := map[string]interface{}{
		"issuer":                                s.URL,
		"authorization_endpoint":                s.URL + "/auth",
		"token_endpoint":                        s.URL + "/token",
		"jwks_uri":                              s.URL + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	buf, err := json.Marshal(conf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(buf)
}

func (s *testOIDCServer) serveToken(w http.ResponseWriter, req *http.Request) {
	clientID, clientSecret := s.clientCreds()
	user, pw, ok := req.BasicAuth()
	var authenticated bool
	if ok {
		authenticated = (user == clientID && pw == clientSecret)
	} else {
		authenticated = (req.Form.Get("client_id") == clientID && req.Form.Get("client_secret") == clientSecret)
	}
	if !authenticated {
		w.Header().Set("WWW-Authenticate", "Basic realm=test-oidc")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client"}`))
		return
	}

	if req.Form.Get("code") != s.code() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	tok := map[string]string{
		"access_token": uuid.New().String(),
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       s.key(),
	}, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	claims := s.claims()
	if claims["iss"] == nil {
		claims["iss"] = s.URL
	}
	tok["id_token"], err = jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	buf, err := json.Marshal(tok)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(buf)
}

func (s *testOIDCServer) serveKeys(w http.ResponseWriter, req *http.Request) {
	jwk := map[string]string{
		"kty": "RSA",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(s.key().PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.key().PublicKey.E)).Bytes()),
	}
	keys := map[string][]map[string]string{
		"keys": {jwk},
	}
	buf, err := json.Marshal(keys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(buf)
}

func (s *testOIDCServer) clientCreds() (id, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clientID == "" {
		s.clientID = uuid.New().String()
		s.clientSecret = uuid.New().String()
	}
	return s.clientID, s.clientSecret
}

func (s *testOIDCServer) code() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.code_ == "" {
		s.code_ = uuid.New().String()
	}
	return s.code_
}

func (s *testOIDCServer) claims() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claims_ == nil {
		s.claims_ = make(map[string]interface{})
	}
	return s.claims_
}

func (s *testOIDCServer) setClaim(name string, v interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claims_ == nil {
		s.claims_ = make(map[string]interface{})
	}
	s.claims_[name] = v
}

func (s *testOIDCServer) key() *rsa.PrivateKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key_ == nil {
		var err error
		s.key_, err = rsa.GenerateKey(rand.Reader, 512)
		if err != nil {
			panic(err)
		}
	}
	return s.key_
}
