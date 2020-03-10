// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package secret_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	qt "github.com/frankban/quicktest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/canonical/candid/idp/idputil/secret"
)

var testKey = bakery.MustGenerateKey()

func TestRoundTrip(t *testing.T) {
	c := qt.New(t)
	codec := secret.NewCodec(testKey)
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, qt.Equals, nil)
	err = codec.Decode(msg, &b)
	c.Assert(err, qt.Equals, nil)
	c.Assert(b, qt.DeepEquals, a)
}

func TestDecodeBadBase64(t *testing.T) {
	c := qt.New(t)
	codec := secret.NewCodec(testKey)
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, qt.Equals, nil)
	msg = "(" + msg[1:]
	err = codec.Decode(msg, &b)
	c.Assert(err, qt.ErrorMatches, "illegal base64 data at input byte 0")
}

func TestDecodeBadPublicKey(t *testing.T) {
	c := qt.New(t)
	codec := secret.NewCodec(testKey)
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, qt.Equals, nil)
	msg = "A" + msg[:len(msg)-1]
	err = codec.Decode(msg, &b)
	c.Assert(err, qt.ErrorMatches, "unknown public key")
	c.Assert(errgo.Cause(err), qt.Equals, secret.ErrDecryption)
}

func TestDecodeDecryptionError(t *testing.T) {
	c := qt.New(t)
	codec := secret.NewCodec(testKey)
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, qt.Equals, nil)
	msg = msg[:44] + msg
	err = codec.Decode(msg, &b)
	c.Assert(err, qt.ErrorMatches, "decryption error")
	c.Assert(errgo.Cause(err), qt.Equals, secret.ErrDecryption)
}

func TestDecodeBufferTooShort(t *testing.T) {
	c := qt.New(t)
	codec := secret.NewCodec(testKey)
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, qt.Equals, nil)
	msg = msg[:40]
	err = codec.Decode(msg, &b)
	c.Assert(err, qt.ErrorMatches, "buffer too short to decode")
}

func TestDecodeUnmarshalError(t *testing.T) {
	c := qt.New(t)
	codec := secret.NewCodec(testKey)
	var a struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	msg, err := codec.Encode(a)
	c.Assert(err, qt.Equals, nil)
	ej := errorJSON{errgo.New("test error")}
	err = codec.Decode(msg, &ej)
	c.Assert(err, qt.ErrorMatches, "test error")
}

func TestEncodeMarshalError(t *testing.T) {
	c := qt.New(t)
	codec := secret.NewCodec(testKey)
	msg, err := codec.Encode(errorJSON{errgo.New("test error")})
	c.Assert(err, qt.ErrorMatches, "json: error calling MarshalJSON for type secret_test.errorJSON: test error")
	c.Assert(msg, qt.Equals, "")
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

func TestCookieRoundTrip(t *testing.T) {
	c := qt.New(t)
	codec := secret.NewCodec(testKey)
	w := httptest.NewRecorder()
	var a, b struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	verification, err := codec.SetCookie(w, "test-cookie", a)
	c.Assert(err, qt.Equals, nil)
	resp := w.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, qt.HasLen, 1)
	c.Assert(cookies[0].Name, qt.Equals, "test-cookie")
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, qt.Equals, nil)
	req.AddCookie(cookies[0])
	err = codec.Cookie(req, "test-cookie", verification, &b)
	c.Assert(err, qt.Equals, nil)
	c.Assert(b, qt.DeepEquals, a)
}

func TestCookieNoCookie(t *testing.T) {
	c := qt.New(t)
	codec := secret.NewCodec(testKey)
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, qt.Equals, nil)
	err = codec.Cookie(req, "test-cookie", "1234", nil)
	c.Assert(err, qt.ErrorMatches, `invalid cookie: http: named cookie not present`)
	c.Assert(errgo.Cause(err), qt.Equals, secret.ErrInvalidCookie)
}

func TestCookieDecodeError(t *testing.T) {
	c := qt.New(t)
	codec := secret.NewCodec(testKey)
	w := httptest.NewRecorder()
	var a struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	_, err := codec.SetCookie(w, "test-cookie", a)
	c.Assert(err, qt.Equals, nil)
	resp := w.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, qt.HasLen, 1)
	c.Assert(cookies[0].Name, qt.Equals, "test-cookie")
	cookies[0].Value = "=" + cookies[0].Value
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, qt.Equals, nil)
	req.AddCookie(cookies[0])
	err = codec.Cookie(req, "test-cookie", "1234", nil)
	c.Assert(err, qt.ErrorMatches, `invalid cookie: illegal base64 data at input byte 0`)
	c.Assert(errgo.Cause(err), qt.Equals, secret.ErrInvalidCookie)
}

func TestCookieValidationError(t *testing.T) {
	c := qt.New(t)
	codec := secret.NewCodec(testKey)
	w := httptest.NewRecorder()
	var a struct {
		A int
		B string
	}
	a.A = 1
	a.B = "test"
	_, err := codec.SetCookie(w, "test-cookie", a)
	c.Assert(err, qt.Equals, nil)
	resp := w.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	c.Assert(cookies, qt.HasLen, 1)
	c.Assert(cookies[0].Name, qt.Equals, "test-cookie")
	req, err := http.NewRequest("", "", nil)
	c.Assert(err, qt.Equals, nil)
	req.AddCookie(cookies[0])
	err = codec.Cookie(req, "test-cookie", "1234", nil)
	c.Assert(err, qt.ErrorMatches, `invalid cookie`)
	c.Assert(errgo.Cause(err), qt.Equals, secret.ErrInvalidCookie)
}
