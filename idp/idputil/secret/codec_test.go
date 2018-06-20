// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package secret_test

import (
	"net/http"
	"net/http/httptest"

	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/candid/idp/idputil/secret"
)

type codecSuite struct {
	key *bakery.KeyPair
}

var _ = gc.Suite(&codecSuite{})

func (s *codecSuite) SetUpSuite(c *gc.C) {
	var err error
	s.key, err = bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
}

func (s *codecSuite) TestRoundTrip(c *gc.C) {
	codec := secret.NewCodec(s.key)
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, gc.Equals, nil)
	err = codec.Decode(msg, &b)
	c.Assert(err, gc.Equals, nil)
	c.Assert(b, jc.DeepEquals, a)
}

func (s *codecSuite) TestDecodeBadBase64(c *gc.C) {
	codec := secret.NewCodec(s.key)
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, gc.Equals, nil)
	msg = "(" + msg[1:]
	err = codec.Decode(msg, &b)
	c.Assert(err, gc.ErrorMatches, "illegal base64 data at input byte 0")
}

func (s *codecSuite) TestDecodeBadPublicKey(c *gc.C) {
	codec := secret.NewCodec(s.key)
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, gc.Equals, nil)
	msg = "A" + msg[:len(msg)-1]
	err = codec.Decode(msg, &b)
	c.Assert(err, gc.ErrorMatches, "unknown public key")
	c.Assert(errgo.Cause(err), gc.Equals, secret.ErrDecryption)
}

func (s *codecSuite) TestDecodeDecryptionError(c *gc.C) {
	codec := secret.NewCodec(s.key)
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, gc.Equals, nil)
	msg = msg[:44] + msg
	err = codec.Decode(msg, &b)
	c.Assert(err, gc.ErrorMatches, "decryption error")
	c.Assert(errgo.Cause(err), gc.Equals, secret.ErrDecryption)
}

func (s *codecSuite) TestDecodeBufferTooShort(c *gc.C) {
	codec := secret.NewCodec(s.key)
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, gc.Equals, nil)
	msg = msg[:40]
	err = codec.Decode(msg, &b)
	c.Assert(err, gc.ErrorMatches, "buffer too short to decode")
}

func (s *codecSuite) TestDecodeUnmarshalError(c *gc.C) {
	codec := secret.NewCodec(s.key)
	var a struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, gc.Equals, nil)
	ej := errorJSON{errgo.New("test error")}
	err = codec.Decode(msg, &ej)
	c.Assert(err, gc.ErrorMatches, "test error")
}

func (s *codecSuite) TestEncodeMarshalError(c *gc.C) {
	codec := secret.NewCodec(s.key)
	msg, err := codec.Encode(errorJSON{errgo.New("test error")})
	c.Assert(err, gc.ErrorMatches, "json: error calling MarshalJSON for type secret_test.errorJSON: test error")
	c.Assert(msg, gc.Equals, "")
}

type errorJSON struct {
	err error
}

func (e errorJSON) MarshalJSON() ([]byte, error) {
	return nil, e.err
}

func (e errorJSON) UnmarshalJSON([]byte) error {
	return e.err
}

func (s *codecSuite) TestCookieRoundTrip(c *gc.C) {
	codec := secret.NewCodec(s.key)
	w := httptest.NewRecorder()
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	verification, err := codec.SetCookie(w, "test-cookie", a)
	c.Assert(err, gc.Equals, nil)
	resp := w.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, gc.HasLen, 1)
	c.Assert(cookies[0].Name, gc.Equals, "test-cookie")
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	req.AddCookie(cookies[0])
	err = codec.Cookie(req, "test-cookie", verification, &b)
	c.Assert(err, gc.Equals, nil)
	c.Assert(b, jc.DeepEquals, a)
}

func (s *codecSuite) TestCookieNoCookie(c *gc.C) {
	codec := secret.NewCodec(s.key)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	err = codec.Cookie(req, "test-cookie", "1234", nil)
	c.Assert(err, gc.ErrorMatches, `invalid cookie: http: named cookie not present`)
	c.Assert(errgo.Cause(err), gc.Equals, secret.ErrInvalidCookie)
}

func (s *codecSuite) TestCookieDecodeError(c *gc.C) {
	codec := secret.NewCodec(s.key)
	w := httptest.NewRecorder()
	var a struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	_, err := codec.SetCookie(w, "test-cookie", a)
	c.Assert(err, gc.Equals, nil)
	resp := w.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, gc.HasLen, 1)
	c.Assert(cookies[0].Name, gc.Equals, "test-cookie")
	cookies[0].Value = "=" + cookies[0].Value
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	req.AddCookie(cookies[0])
	err = codec.Cookie(req, "test-cookie", "1234", nil)
	c.Assert(err, gc.ErrorMatches, `invalid cookie: illegal base64 data at input byte 0`)
	c.Assert(errgo.Cause(err), gc.Equals, secret.ErrInvalidCookie)
}

func (s *codecSuite) TestCookieValidationError(c *gc.C) {
	codec := secret.NewCodec(s.key)
	w := httptest.NewRecorder()
	var a struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	_, err := codec.SetCookie(w, "test-cookie", a)
	c.Assert(err, gc.Equals, nil)
	resp := w.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, gc.HasLen, 1)
	c.Assert(cookies[0].Name, gc.Equals, "test-cookie")
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, gc.Equals, nil)
	req.AddCookie(cookies[0])
	err = codec.Cookie(req, "test-cookie", "1234", nil)
	c.Assert(err, gc.ErrorMatches, `invalid cookie`)
	c.Assert(errgo.Cause(err), gc.Equals, secret.ErrInvalidCookie)
}
