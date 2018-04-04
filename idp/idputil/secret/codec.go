// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package secret

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"golang.org/x/crypto/nacl/box"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

var ErrDecryption = errgo.New("decryption error")

// Codec is used to create an encrypted messages that will be decrypted
// by the same service. This should be used for cookies and other data
// that needs to be sent through the client but must be verifiable as
// originally coming from this service.
type Codec struct {
	public, shared *[bakery.KeyLen]byte
}

// NewCodec creates a new Codec using the given key.
func NewCodec(key *bakery.KeyPair) *Codec {
	shared := new([bakery.KeyLen]byte)
	box.Precompute(shared, (*[bakery.KeyLen]byte)(&key.Public.Key), (*[bakery.KeyLen]byte)(&key.Private.Key))
	return &Codec{
		public: (*[bakery.KeyLen]byte)(&key.Public.Key),
		shared: shared,
	}
}

// Encode marshals the given value in such a way that it can only be
// unmarshaled by a Codec using the same key. The encoded output will be
// in the base64 url safe alphabet.
func (c *Codec) Encode(v interface{}) (string, error) {
	msg, err := json.Marshal(v)
	if err != nil {
		return "", errgo.Mask(err)
	}
	out := make([]byte, 0, bakery.KeyLen+bakery.NonceLen+len(msg)+box.Overhead)
	out, err = c.encrypt(out, msg)
	if err != nil {
		return "", errgo.Mask(err)
	}
	return base64.URLEncoding.EncodeToString(out), nil
}

// encrypt encrypts the given message.
func (c *Codec) encrypt(out, msg []byte) ([]byte, error) {
	var nonce [bakery.NonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errgo.Mask(err)
	}
	out = append(out, c.public[:]...)
	out = append(out, nonce[:]...)
	out = box.SealAfterPrecomputation(out, msg, &nonce, c.shared)
	return out, nil
}

// Decode unmarshals a value from the given buffer that must have been
// marshaled with a Codec using the same key. If there was an error
// decrypting buf the returned error will have a cause of ErrDecryption.
func (c *Codec) Decode(s string, v interface{}) error {
	buf, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return errgo.Mask(err)
	}
	if len(buf) < bakery.KeyLen+bakery.NonceLen+box.Overhead {
		return errgo.New("buffer too short to decode")
	}
	out := make([]byte, 0, len(buf)-bakery.KeyLen-bakery.NonceLen-box.Overhead)
	out, err = c.decrypt(out, buf)
	if err != nil {
		return errgo.Mask(err, errgo.Is(ErrDecryption))
	}
	return errgo.Mask(json.Unmarshal(out, v))
}

// decrypt decrypts the message from the encrypted data. The given value
// of must be long enough to contain at least the public key, nonce and
// box.Overhead.
func (c *Codec) decrypt(out, in []byte) ([]byte, error) {
	var public [bakery.KeyLen]byte
	var nonce [bakery.NonceLen]byte
	copy(public[:], in)
	if public != *c.public {
		return nil, errgo.WithCausef(nil, ErrDecryption, "unknown public key")
	}
	copy(nonce[:], in[len(public):])
	out, ok := box.OpenAfterPrecomputation(out, in[len(public)+len(nonce):], &nonce, c.shared)
	if !ok {
		return nil, ErrDecryption
	}
	return out, nil
}
