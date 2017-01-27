// Copyright 2017 Canonical Ltd.

package secret_test

import (
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"

	"github.com/CanonicalLtd/blues-identity/idp/idputil/secret"
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
