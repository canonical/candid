// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package ussodischarge_test

import (
	"encoding/json"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/candid/v2/candidclient/ussodischarge"
)

func TestUnmarshalUSSOMacaroon(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	data := []byte(`"MDAxYmxvY2F0aW9uIHRlc3QgbG9jYXRpb24KMDAxZGlkZW50aWZpZXIgdGVzdCBtYWNhcm9vbgowMDJmc2lnbmF0dXJlICaaplwsJeHwPuBK6er_d3DnEnSJ2b85-V9SXsiL6xWOCg"`)
	var m ussodischarge.USSOMacaroon
	err := json.Unmarshal(data, &m)
	c.Assert(err, qt.IsNil)
	c.Assert(string(m.Macaroon.Id()), qt.Equals, "test macaroon")
}

func TestUnmarshalUSSOMacaroonNotJSONString(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	data := []byte(`123`)
	var m ussodischarge.USSOMacaroon
	err := json.Unmarshal(data, &m)
	c.Assert(err, qt.ErrorMatches, `cannot unmarshal macaroon: json: cannot unmarshal number into Go value of type string`)
}

func TestUnmarshalUSSOMacaroonBadBase64(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	data := []byte(`"MDAxYmxvY2F0aW9uIHRlc3QgbG9jYXRpb24KMDAxZGlkZW50aWZpZXIgdGVzdCBtYWNhcm9vbgowMDJmc2lnbmF0dXJlICaaplwsJeHwPuBK6er/d3DnEnSJ2b85+V9SXsiL6xWOCg"`)
	var m ussodischarge.USSOMacaroon
	err := json.Unmarshal(data, &m)
	c.Assert(err, qt.ErrorMatches, `cannot unmarshal macaroon: illegal base64 data at input byte 111`)
}

func TestUnmarshalUSSOMacaroonBadBinary(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	data := []byte(`"NDAxYmxvY2F0aW9uIHRlc3QgbG9jYXRpb24KMDAxZGlkZW50aWZpZXIgdGVzdCBtYWNhcm9vbgowMDJmc2lnbmF0dXJlICaaplwsJeHwPuBK6er_d3DnEnSJ2b85-V9SXsiL6xWOCg"`)
	var m ussodischarge.USSOMacaroon
	err := json.Unmarshal(data, &m)
	c.Assert(err, qt.ErrorMatches, `cannot unmarshal macaroon: unmarshal v1: packet size too big`)
}
