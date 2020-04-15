// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package ussodischarge_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	macaroon "gopkg.in/macaroon.v2"
	yaml "gopkg.in/yaml.v2"

	udclient "github.com/canonical/candid/candidclient/ussodischarge"
	"github.com/canonical/candid/config"
	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/idptest"
	"github.com/canonical/candid/idp/usso/ussodischarge"
	"github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/store"
)

func TestConfig(t *testing.T) {
	c := qt.New(t)
	configYaml := `
identity-providers:
 - type: usso_macaroon
   url: https://login.ubuntu.com
   domain: ussotest
   public-key: |
     -----BEGIN PUBLIC KEY-----
     MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviBpgY6CXh9MEZTBJUbV
     v34mHCHLGCQnfP2OMQjDXkqvdXZp6EEO9wgvO6Xjh1ByoP2K0Qqbikfgi/I5cOrn
     JKPrt85RrKfWYIwTykBUaPWO5AsAxvb/+L4gXXDNYaYxL/kmRpP+45qVmOFdK4yX
     adtdzYUBmH8BFfTPn5RwlHU+9jrFJkidlWDCrocJiJZdeBYxlu4kIK1hLF1HhnQ9
     sG2iy/4GUS9QFuQVwBHPett2ANC/lUn0MbPNo8YVOTg9pswKteFNWUP7pcGWwPIn
     ktjFFKBWXIaTZs33KeWfFzUkArwCqmz7YOCms+pB3V6YrTCO0gOqXRnj6SqUkKWA
     xQIDAQAB
     -----END PUBLIC KEY-----
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(configYaml), &conf)
	c.Assert(err, qt.IsNil)
	c.Assert(conf.IdentityProviders, qt.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), qt.Equals, "usso_macaroon")
}

func TestSuite(t *testing.T) {
	qtsuite.Run(qt.New(t), &ussoMacaroonSuite{})
}

type ussoMacaroonSuite struct {
	*fixture
}

type fixture struct {
	idptest *idptest.Fixture
	idp     idp.IdentityProvider
}

func newFixture(c *qt.C) *fixture {
	f := &fixture{
		idptest: idptest.NewFixture(c, candidtest.NewStore()),
	}

	var err error
	f.idp, err = ussodischarge.NewIdentityProvider(ussodischarge.Params{
		URL:    "https://login.staging.ubuntu.com",
		Domain: "ussotest",
		PublicKey: ussodischarge.PublicKey{
			PublicKey: testKey.PublicKey,
		},
	})
	c.Assert(err, qt.IsNil)
	err = f.idp.Init(f.idptest.Ctx, f.idptest.InitParams(c, "https://idp.test"))
	c.Assert(err, qt.IsNil)
	return f
}

func (s *ussoMacaroonSuite) Init(c *qt.C) {
	s.fixture = newFixture(c)
}

func (s *ussoMacaroonSuite) TestName(c *qt.C) {
	c.Assert(s.idp.Name(), qt.Equals, "usso_macaroon")
}

func (s *ussoMacaroonSuite) TestDescription(c *qt.C) {
	c.Assert(s.idp.Description(), qt.Equals, "Ubuntu SSO macaroon discharge authentication")
}

func (s *ussoMacaroonSuite) TestIconURL(c *qt.C) {
	c.Assert(s.idp.IconURL(), qt.Equals, "")
}

func (s *ussoMacaroonSuite) TestInteractive(c *qt.C) {
	c.Assert(s.idp.Interactive(), qt.Equals, false)
}

func (s *ussoMacaroonSuite) TestHidden(c *qt.C) {
	c.Assert(s.idp.Hidden(), qt.Equals, false)
}

func (s *ussoMacaroonSuite) TestURL(c *qt.C) {
	t := s.idp.URL("1")
	c.Assert(t, qt.Equals, "https://idp.test/login?id=1")
}

func (s *ussoMacaroonSuite) TestHandleGetSuccess(c *qt.C) {
	req, err := http.NewRequest("GET", "/login", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	c.Assert(rr.Code, qt.Equals, http.StatusOK, qt.Commentf("%s", rr.Body))
	var mresp udclient.MacaroonResponse
	err = json.Unmarshal(rr.Body.Bytes(), &mresp)
	c.Assert(err, qt.IsNil)
	m := mresp.Macaroon.M()
	cavs := m.Caveats()
	var thirdPartyCav macaroon.Caveat
	for _, cav := range cavs {
		if len(cav.VerificationId) != 0 {
			thirdPartyCav = cav
		}
	}
	c.Assert(thirdPartyCav.VerificationId, qt.Not(qt.HasLen), 0)
	var cid ussodischarge.USSOCaveatID
	err = json.Unmarshal(thirdPartyCav.Id, &cid)
	c.Assert(err, qt.IsNil)
	c.Assert(cid.Version, qt.Equals, 1)
	secret, err := base64.StdEncoding.DecodeString(cid.Secret)
	c.Assert(err, qt.IsNil)
	rk, err := rsa.DecryptOAEP(sha1.New(), nil, testKey, secret, nil)
	c.Assert(err, qt.IsNil)
	md, err := macaroon.New(rk, thirdPartyCav.Id, "test", macaroon.V1)
	c.Assert(err, qt.IsNil)
	md.Bind(m.Signature())
	ms := macaroon.Slice{m, md}
	checker := identchecker.NewChecker(identchecker.CheckerParams{
		MacaroonVerifier: s.idptest.Oven,
	})
	authInfo, err := checker.Auth(ms).Allow(s.idptest.Ctx, ussodischarge.USSOLoginOp)
	c.Assert(err, qt.IsNil)
	c.Assert(authInfo.Identity, qt.Equals, nil)
}

func (s *ussoMacaroonSuite) TestHandleGetV1Success(c *qt.C) {
	req, err := http.NewRequest("GET", "/interact", nil)
	c.Assert(err, qt.IsNil)
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	c.Assert(rr.Code, qt.Equals, http.StatusOK, qt.Commentf("%s", rr.Body))
	var mresp udclient.MacaroonResponse
	err = json.Unmarshal(rr.Body.Bytes(), &mresp)
	c.Assert(err, qt.IsNil)
	m := mresp.Macaroon.M()
	cavs := m.Caveats()
	var thirdPartyCav macaroon.Caveat
	for _, cav := range cavs {
		if len(cav.VerificationId) != 0 {
			thirdPartyCav = cav
		}
	}
	c.Assert(thirdPartyCav.VerificationId, qt.Not(qt.HasLen), 0)
	var cid ussodischarge.USSOCaveatID
	err = json.Unmarshal(thirdPartyCav.Id, &cid)
	c.Assert(err, qt.IsNil)
	c.Assert(cid.Version, qt.Equals, 1)
	secret, err := base64.StdEncoding.DecodeString(cid.Secret)
	c.Assert(err, qt.IsNil)
	rk, err := rsa.DecryptOAEP(sha1.New(), nil, testKey, secret, nil)
	c.Assert(err, qt.IsNil)
	md, err := macaroon.New(rk, thirdPartyCav.Id, "test", macaroon.V1)
	c.Assert(err, qt.IsNil)
	md.Bind(m.Signature())
	ms := macaroon.Slice{m, md}
	checker := identchecker.NewChecker(identchecker.CheckerParams{
		MacaroonVerifier: s.idptest.Oven,
	})
	authInfo, err := checker.Auth(ms).Allow(s.idptest.Ctx, ussodischarge.USSOLoginOp)
	c.Assert(err, qt.IsNil)
	c.Assert(authInfo.Identity, qt.Equals, nil)
}

var postTests = []struct {
	about        string
	account      *ussodischarge.AccountInfo
	validSince   string
	lastAuth     string
	expires      string
	extraCaveats []string
	expectUser   *store.Identity
	expectError  string
}{{
	about: "success",
	account: &ussodischarge.AccountInfo{
		Username:    "username",
		OpenID:      "1234567",
		Email:       "testuser@example.com",
		DisplayName: "Test User",
	},
	validSince: timeString(-time.Hour),
	lastAuth:   timeString(-time.Minute),
	expires:    timeString(time.Hour),
	expectUser: &store.Identity{
		ProviderID: store.MakeProviderIdentity("usso_macaroon", "1234567"),
		Username:   "1234567@ussotest",
		Name:       "Test User",
		Email:      "testuser@example.com",
	},
}, {
	about:       "no account",
	validSince:  timeString(-time.Hour),
	lastAuth:    timeString(-time.Minute),
	expires:     timeString(time.Hour),
	expectError: "account information not specified",
}, {
	about: "expires bad format",
	account: &ussodischarge.AccountInfo{
		Username:    "username",
		OpenID:      "1234567",
		Email:       "testuser@example.com",
		DisplayName: "Test User",
	},
	validSince:  timeString(-time.Hour),
	lastAuth:    timeString(-time.Minute),
	expires:     "never",
	expectError: `verification failed \(USSO caveat\): expires caveat badly formed: parsing time "never" as "2006-01-02T15:04:05.000000": cannot parse "never" as "2006"`,
}, {
	about: "expires in past",
	account: &ussodischarge.AccountInfo{
		Username:    "username",
		OpenID:      "1234567",
		Email:       "testuser@example.com",
		DisplayName: "Test User",
	},
	validSince:  timeString(-time.Hour),
	lastAuth:    timeString(-time.Minute),
	expires:     timeString(-time.Hour),
	expectError: `verification failed \(USSO caveat\): expires before current time`,
}, {
	about: "multiple account info",
	account: &ussodischarge.AccountInfo{
		Username:    "username",
		OpenID:      "1234567",
		Email:       "testuser@example.com",
		DisplayName: "Test User",
	},
	validSince:   timeString(-time.Hour),
	lastAuth:     timeString(-time.Minute),
	expires:      timeString(time.Hour),
	extraCaveats: []string{`login.staging.ubuntu.com|account|{"username": "failuser"}`},
	expectError:  `verification failed \(USSO caveat\): account specified inconsistently`,
}, {
	about: "unrecognised caveat",
	account: &ussodischarge.AccountInfo{
		Username:    "username",
		OpenID:      "1234567",
		Email:       "testuser@example.com",
		DisplayName: "Test User",
	},
	validSince:   timeString(-time.Hour),
	lastAuth:     timeString(-time.Minute),
	expires:      timeString(time.Hour),
	extraCaveats: []string{`login.staging.ubuntu.com|no-such-condition|fail`},
	expectError:  `verification failed \(USSO caveat\): unknown caveat "no-such-condition"`,
}, {
	about:        "account bad base64",
	validSince:   timeString(-time.Hour),
	lastAuth:     timeString(-time.Minute),
	expires:      timeString(time.Hour),
	extraCaveats: []string{`login.staging.ubuntu.com|account|f`},
	expectError:  `verification failed \(USSO caveat\): account caveat badly formed: illegal base64 data at input byte 0`,
}, {
	about:        "account bad json",
	validSince:   timeString(-time.Hour),
	lastAuth:     timeString(-time.Minute),
	expires:      timeString(time.Hour),
	extraCaveats: []string{`login.staging.ubuntu.com|account|fQ==`},
	expectError:  `verification failed \(USSO caveat\): account caveat badly formed: invalid character '}' looking for beginning of value`,
}, {
	about: "without argument",
	account: &ussodischarge.AccountInfo{
		Username:    "username",
		OpenID:      "1234567",
		Email:       "testuser@example.com",
		DisplayName: "Test User",
	},
	validSince:   timeString(-time.Hour),
	lastAuth:     timeString(-time.Minute),
	expires:      timeString(time.Hour),
	extraCaveats: []string{`login.staging.ubuntu.com|no-arg`},
	expectError:  `verification failed \(USSO caveat\): no argument provided in "login.staging.ubuntu.com\|no-arg"`,
}}

func (s *ussoMacaroonSuite) TestHandlePostV1(c *qt.C) {
	err := s.idp.Init(s.idptest.Ctx, s.idptest.InitParams(c, "https://idp.test"))
	c.Assert(err, qt.IsNil)
	bm, err := s.idptest.Oven.NewMacaroon(s.idptest.Ctx, bakery.Version1, nil, ussodischarge.USSOLoginOp)
	c.Assert(err, qt.IsNil)
	m := bm.M()
	buf, err := json.Marshal(&ussodischarge.AccountInfo{
		Username:    "username",
		OpenID:      "1234567",
		Email:       "testuser@example.com",
		DisplayName: "Test User",
	})
	c.Assert(err, qt.IsNil)
	err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|account|" + base64.StdEncoding.EncodeToString(buf)))
	c.Assert(err, qt.IsNil)

	err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|valid_since|" + timeString(-time.Hour)))
	c.Assert(err, qt.IsNil)

	err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|last_auth|" + timeString(-time.Minute)))
	c.Assert(err, qt.IsNil)
	err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|expires|" + timeString(time.Hour)))
	c.Assert(err, qt.IsNil)
	body := udclient.Login{
		Macaroons: macaroon.Slice{m},
	}
	buf, err = json.Marshal(body)
	c.Assert(err, qt.IsNil)
	req, err := http.NewRequest("POST", "/interact", bytes.NewReader(buf))
	c.Assert(err, qt.IsNil)
	req.Header.Set("Content-Type", "application/json")
	req.ParseForm()
	rr := httptest.NewRecorder()
	s.idp.Handle(s.idptest.Ctx, rr, req)
	c.Assert(rr.Code, qt.Equals, http.StatusOK)
	c.Assert(rr.HeaderMap.Get("Content-Type"), qt.Equals, "application/json")
	var resp udclient.LoginResponse
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	c.Assert(err, qt.IsNil)
	c.Assert(resp, qt.DeepEquals, udclient.LoginResponse{
		DischargeToken: &httpbakery.DischargeToken{
			Kind:  "test",
			Value: []byte("1234567@ussotest"),
		},
	})
}

func TestHandlePost(t *testing.T) {
	c := qt.New(t)
	defer c.Done()
	for _, test := range postTests {
		c.Run(test.about, func(c *qt.C) {
			f := newFixture(c)
			err := f.idp.Init(f.idptest.Ctx, f.idptest.InitParams(c, "https://idp.test"))
			c.Assert(err, qt.IsNil)
			bm, err := f.idptest.Oven.NewMacaroon(f.idptest.Ctx, bakery.Version1, nil, ussodischarge.USSOLoginOp)
			c.Assert(err, qt.IsNil)
			m := bm.M()
			if test.account != nil {
				buf, err := json.Marshal(test.account)
				c.Assert(err, qt.IsNil)
				err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|account|" + base64.StdEncoding.EncodeToString(buf)))
				c.Assert(err, qt.IsNil)
			}
			if test.validSince != "" {
				err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|valid_since|" + test.validSince))
				c.Assert(err, qt.IsNil)
			}
			if test.lastAuth != "" {
				err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|last_auth|" + test.lastAuth))
				c.Assert(err, qt.IsNil)
			}
			if test.expires != "" {
				err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|expires|" + test.expires))
				c.Assert(err, qt.IsNil)
			}
			for _, cav := range test.extraCaveats {
				err = m.AddFirstPartyCaveat([]byte(cav))
				c.Assert(err, qt.IsNil)
			}
			body := udclient.Login{
				Macaroons: macaroon.Slice{m},
			}
			buf, err := json.Marshal(body)
			c.Assert(err, qt.IsNil)
			req, err := http.NewRequest("POST", "/login", bytes.NewReader(buf))
			c.Assert(err, qt.IsNil)
			req.Header.Set("Content-Type", "application/json")
			req.ParseForm()
			rr := httptest.NewRecorder()
			f.idp.Handle(f.idptest.Ctx, rr, req)
			if test.expectError != "" {
				f.idptest.AssertLoginFailureMatches(c, test.expectError)
				return
			}
			f.idptest.AssertLoginSuccess(c, test.expectUser.Username)
			f.idptest.Store.AssertUser(c, test.expectUser)
		})
	}
}

func TestMultipleLogins(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	f := newFixture(c)
	err := f.idp.Init(f.idptest.Ctx, f.idptest.InitParams(c, "https://idp.test"))
	c.Assert(err, qt.IsNil)

	dologin := func(ai *ussodischarge.AccountInfo) {
		bm, err := f.idptest.Oven.NewMacaroon(f.idptest.Ctx, bakery.Version1, nil, ussodischarge.USSOLoginOp)
		c.Assert(err, qt.IsNil)
		m := bm.M()
		buf, err := json.Marshal(ai)
		c.Assert(err, qt.IsNil)
		err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|account|" + base64.StdEncoding.EncodeToString(buf)))
		c.Assert(err, qt.IsNil)
		err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|valid_since|" + timeString(-time.Minute)))
		c.Assert(err, qt.IsNil)
		err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|last_auth|" + timeString(-time.Hour)))
		c.Assert(err, qt.IsNil)
		err = m.AddFirstPartyCaveat([]byte("login.staging.ubuntu.com|expires|" + timeString(time.Hour)))
		c.Assert(err, qt.IsNil)

		body := udclient.Login{
			Macaroons: macaroon.Slice{m},
		}
		buf, err = json.Marshal(body)
		c.Assert(err, qt.IsNil)
		req, err := http.NewRequest("POST", "/login", bytes.NewReader(buf))
		c.Assert(err, qt.IsNil)
		req.Header.Set("Content-Type", "application/json")
		req.ParseForm()
		rr := httptest.NewRecorder()
		f.idp.Handle(f.idptest.Ctx, rr, req)
		f.idptest.AssertLoginSuccess(c, ai.OpenID+"@ussotest")
		f.idptest.Store.AssertUser(c, &store.Identity{
			ProviderID: store.MakeProviderIdentity("usso_macaroon", ai.OpenID),
			Username:   ai.OpenID + "@ussotest",
			Name:       ai.DisplayName,
			Email:      ai.Email,
		})
	}

	dologin(&ussodischarge.AccountInfo{
		Username:    "username1",
		OpenID:      "1234568",
		Email:       "testuser1@example.com",
		DisplayName: "Test User",
	})
	f.idptest.Reset()
	dologin(&ussodischarge.AccountInfo{
		Username:    "username2",
		OpenID:      "1234569",
		Email:       "testuser2@example.com",
		DisplayName: "Test User II",
	})
}

func timeString(d time.Duration) string {
	return time.Now().Add(d).UTC().Format(ussodischarge.TimeFormat)
}

var testKey *rsa.PrivateKey

func init() {
	block, _ := pem.Decode([]byte(testKeyPEM))
	var err error
	testKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
}

// testKey generated by openssl
const testKeyPEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2gZGJUvSl0NHkq5u4RDwNYIe3Yc5U5a95anmFVTZU70HNICJ
GAZkEgDZPnbz/gv41r4qMXO30I27jHNUJluq7KeEnG0SJPpiZcawZ4GTvao5e9aQ
cD0alENo0qyyND1xseyQ1VEKlb1D6Sik9y+yyNcgbE8H5MjO/zERL6IsAPILeYJv
oAYnLmv0fj49HIR8c+U7Xz61M0Khwt2U/3Ou4JnRH+6gdhLRvsUbd9GFu6GsEHQn
YAH9xrkY8458Oj6L7kEbezVbVH6J4a3LtLo0MZrDNeCGKRL0rNf6me3FRctSFHhJ
bCUlnGOF/FkVnVleyFAzebTA3Wvnrnax4XtlyQIDAQABAoIBAQDVe8c7xd7TVoHC
0yKnJxrOijcG2936R2RyecZdpNOY90MS2blj2P4r0sDmNTv8ymRCgbp26cRXZjD6
+gKv/JqFWBK1yOc3ZiTrW35oG606zm+zHwoXnP1lqAwAHjHwjSnC+s1m0w/2R3kz
2SSPFhmOJ3gMFea40xg9MSKO7dEAqjGnnj0iRkGqLw1KJArvcj6qaBAq3xFBC9+A
/YWCj6xkyFRzbQ0pu08TwtU6m4WVkAzXAUWo8wdrhAAn569AQiIQB0OMEqhNWGUw
ZMimterRyfqIbDWGaEeQkocveRikogf7DnC0gOy8DSacGDzdFeI8GBuNURdTeFDS
Di3mc++xAoGBAPrzhsoso3MCgBJF1v21+DBrR62BORJoXDXvQtTW5T5Vrc18KTEg
sBBUgMlqaW21TYiCDm9wFqm7B1h6gVMupebvp0wFXogearLH1/uMsILxjhLFRfZS
S+6GSB0i/w7k7zVpQ6UNz3x6Ab/DsM1Fqi8NSGxSl+undsxmyX3IxMj7AoGBAN5p
KjTGhknU43HIH6z66Z8q6ZBH8spBCsTxkV+yhFO00oqvjrtHPvHNAHudaqVuroKq
Fyiyf2B/f1g5s8mzpq1xdHDF/7i9BiemN9FKlznUDHLV9+c5xKeNrzjHd4c78Lnj
z9NyOgSc0DgFwj2xn6WdJjm8Mogu/FFpu6kr3tkLAoGBANBeBD06czy7hrulYa2n
ujv517oo4cp2/JmL4GH5TL9FRNqpjUpNaeMlRwn2YTPGpmoCExpUZ3zm3mKI1XjL
8tSdiLuGecdr+gwYAy3K04TmLKFJS54LFyEmPhpzRHSJglVG4fPaU713UJx5UAQh
I/2NeeT3b00r72gosITQfxShAoGBAKdkhVSVOkrlRI3Fbjm12xFlrcZesFgTHfTe
T2i0Ji4OAQxKV2WSmMhKX5up/bMnG4bSV33U4lORghm3zB357W/K3TVngDDda315
97a4qhrnAruHWP6Zlu34kDFuxwJsVaDC2g8tgIcqMviHNQtT3XE7VqLLh0jB/DuW
FZycnSvDAoGAM7vHz15cvi1ivq4I3KNmHTmQa2oMZ5NeBXRGFC5ptnPG4jkNaOIa
1vFY042om4AF5dt5OJaO7wmYwrWOUpVnFEvOS9gi/ucLahgplGJCg3tY3j52J6Gp
OJYm1M7VAWvhigBzfa2tw7w76HbyF79t4e67tVJACs1ABk4Sqr1Ds9Q=
-----END RSA PRIVATE KEY-----
`
