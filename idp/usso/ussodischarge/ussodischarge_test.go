// Copyright 2016 Canonical Ltd.

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
	"time"

	"github.com/juju/idmclient/params"
	udclient "github.com/juju/idmclient/ussodischarge"
	"github.com/juju/testing"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	macaroon "gopkg.in/macaroon.v2-unstable"
	yaml "gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/usso/ussodischarge"
)

type ussoMacaroonSuite struct {
	testing.IsolatedMgoSuite
	idp    idp.IdentityProvider
	bakery *bakery.Bakery
}

var _ = gc.Suite(&ussoMacaroonSuite{})

func (s *ussoMacaroonSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	key, err := bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)

	s.bakery = bakery.New(bakery.BakeryParams{
		Key: key,
	})
	c.Assert(err, gc.Equals, nil)
	s.idp, err = ussodischarge.NewIdentityProvider(ussodischarge.Params{
		URL:    "https://login.staging.ubuntu.com",
		Domain: "ussotest",
		PublicKey: ussodischarge.PublicKey{
			PublicKey: testKey.PublicKey,
		},
	})
	c.Assert(err, gc.Equals, nil)
}

func (s *ussoMacaroonSuite) TestConfig(c *gc.C) {
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
	c.Assert(err, gc.IsNil)
	c.Assert(conf.IdentityProviders, gc.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), gc.Equals, "usso_macaroon")
}

func (s *ussoMacaroonSuite) TestName(c *gc.C) {
	c.Assert(s.idp.Name(), gc.Equals, "usso_macaroon")
}

func (s *ussoMacaroonSuite) TestDescription(c *gc.C) {
	c.Assert(s.idp.Description(), gc.Equals, "Ubuntu SSO macaroon discharge authentication")
}

func (s *ussoMacaroonSuite) TestInteractive(c *gc.C) {
	c.Assert(s.idp.Interactive(), gc.Equals, false)
}

func (s *ussoMacaroonSuite) TestURL(c *gc.C) {
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Database_: s.Session.DB("test"),
	}
	t, err := s.idp.URL(tc, "1")
	c.Assert(err, gc.Equals, nil)
	c.Assert(t, gc.Equals, "https://idp.test/login?waitid=1")
}

func (s *ussoMacaroonSuite) TestHandleGetSuccess(c *gc.C) {
	req, err := http.NewRequest("GET", "https://idp.test", nil)
	c.Assert(err, gc.Equals, nil)
	tc := &idptest.TestContext{
		URLPrefix: "https://idp.test",
		Bakery_:   s.bakery,
		Database_: s.Session.DB("test"),
		Request:   req,
	}
	s.idp.Handle(tc)
	resp := tc.Response()
	c.Assert(resp.Code, gc.Equals, http.StatusOK, gc.Commentf("%s", resp.Body))
	var mresp udclient.MacaroonResponse
	err = json.Unmarshal(resp.Body.Bytes(), &mresp)
	c.Assert(err, gc.Equals, nil)
	m := mresp.Macaroon.M()
	cavs := m.Caveats()
	var thirdPartyCav macaroon.Caveat
	for _, cav := range cavs {
		if len(cav.VerificationId) != 0 {
			thirdPartyCav = cav
		}
	}
	c.Assert(thirdPartyCav.VerificationId, gc.Not(gc.HasLen), 0)
	var cid ussodischarge.USSOCaveatID
	err = json.Unmarshal(thirdPartyCav.Id, &cid)
	c.Assert(err, gc.Equals, nil)
	c.Assert(cid.Version, gc.Equals, 1)
	secret, err := base64.StdEncoding.DecodeString(cid.Secret)
	c.Assert(err, gc.Equals, nil)
	rk, err := rsa.DecryptOAEP(sha1.New(), nil, testKey, secret, nil)
	c.Assert(err, gc.Equals, nil)
	md, err := macaroon.New(rk, thirdPartyCav.Id, "test", macaroon.V1)
	c.Assert(err, gc.Equals, nil)
	md.Bind(m.Signature())
	ms := macaroon.Slice{m, md}
	authInfo, err := s.bakery.Checker.Auth(ms).Allow(context.TODO(), ussodischarge.USSOLoginOp)
	c.Assert(err, gc.Equals, nil)
	c.Assert(authInfo.Identity, gc.Equals, nil)
}

var postTests = []struct {
	about        string
	account      *ussodischarge.AccountInfo
	validSince   string
	lastAuth     string
	expires      string
	extraCaveats []string
	expectUser   *params.User
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
	expectUser: &params.User{
		Username:   "1234567@ussotest",
		ExternalID: "ussotest-openid:1234567",
		FullName:   "Test User",
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
	expectError:  `verification failed \(USSO caveat\): account specified multiple times`,
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
	expectError:  `verification failed \(USSO caveat\): no argument provided in "login.staging.ubuntu.com|no-arg"`,
}}

func (s *ussoMacaroonSuite) TestHandlePost(c *gc.C) {
	for i, test := range postTests {
		c.Logf("%d. %s", i, test.about)
		bm, err := s.bakery.Oven.NewMacaroon(context.TODO(), bakery.Version1, time.Now().Add(time.Minute), nil, ussodischarge.USSOLoginOp)
		c.Assert(err, gc.Equals, nil)
		m := bm.M()
		if test.account != nil {
			buf, err := json.Marshal(test.account)
			c.Assert(err, gc.Equals, nil)
			err = m.AddFirstPartyCaveat("login.staging.ubuntu.com|account|" + base64.StdEncoding.EncodeToString(buf))
			c.Assert(err, gc.Equals, nil)
		}
		if test.validSince != "" {
			err = m.AddFirstPartyCaveat("login.staging.ubuntu.com|valid_since|" + test.validSince)
			c.Assert(err, gc.Equals, nil)
		}
		if test.lastAuth != "" {
			err = m.AddFirstPartyCaveat("login.staging.ubuntu.com|last_auth|" + test.lastAuth)
			c.Assert(err, gc.Equals, nil)
		}
		if test.expires != "" {
			err = m.AddFirstPartyCaveat("login.staging.ubuntu.com|expires|" + test.expires)
			c.Assert(err, gc.Equals, nil)
		}
		for _, cav := range test.extraCaveats {
			err = m.AddFirstPartyCaveat(cav)
			c.Assert(err, gc.Equals, nil)
		}
		body := udclient.Login{
			Macaroons: macaroon.Slice{m},
		}
		buf, err := json.Marshal(body)
		c.Assert(err, gc.Equals, nil)
		req, err := http.NewRequest("POST", "https://idp.test", bytes.NewReader(buf))
		c.Assert(err, gc.Equals, nil)
		req.Header.Set("Content-Type", "application/json")
		tc := &idptest.TestContext{
			URLPrefix: "https://idp.test",
			Bakery_:   s.bakery,
			Database_: s.Session.DB("test"),
			Request:   req,
		}
		s.idp.Handle(tc)
		if test.expectError != "" {
			idptest.AssertLoginFailure(c, tc, test.expectError)
			continue
		}
		idptest.AssertLoginSuccess(c, tc, test.expectUser.Username)
		idptest.AssertUser(c, tc, test.expectUser)
	}
}

func timeString(d time.Duration) string {
	return time.Now().Add(d).Format(ussodischarge.TimeFormat)
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
