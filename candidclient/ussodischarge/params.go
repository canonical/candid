// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package ussodischarge

import (
	"encoding/base64"
	"encoding/json"

	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon.v2"
)

// MacaroonResponse is the response from a GET to a usso-macaroon
// identity provider, it will be a macaroon with a third party discharge
// addressed to an Ubuntu SSO service.
type MacaroonResponse struct {
	Macaroon *bakery.Macaroon `json:"macaroon,omitempty"`
}

// LoginRequest is a request to log in using a macaroon that has been
// discharged by an Ubuntu SSO service.
type LoginRequest struct {
	httprequest.Route `httprequest:"POST"`
	Login             Login `httprequest:",body"`
}

// Login is the body of a LoginRequest.
type Login struct {
	Macaroons macaroon.Slice `json:"macaroons,omitempty"`
}

// LoginResponse is the response to a LoginReuest.
type LoginResponse struct {
	DischargeToken *httpbakery.DischargeToken `json:"discharge-token"`
}

// ussoDischargeRequest is the request to Ubuntu SSO to discharge a
// caveat on behalf of a user.
type ussoDischargeRequest struct {
	httprequest.Route `httprequest:"POST /api/v2/tokens/discharge"`
	Discharge         ussoDischarge `httprequest:",body"`
}

// ussoDischarge is the body of a ussoDischargeRequest.
type ussoDischarge struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	OTP      string `json:"otp,omitempty"`
	CaveatID string `json:"caveat_id"`
}

// ussoDischargeResponse is the response from a ussoDischargeRequest
type ussoDischargeResponse struct {
	Macaroon ussoMacaroon `json:"discharge_macaroon"`
}

type ussoMacaroon struct {
	macaroon.Macaroon
}

func (m *ussoMacaroon) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errgo.Notef(err, "cannot unmarshal macaroon")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return errgo.Notef(err, "cannot unmarshal macaroon")
	}
	if err := m.Macaroon.UnmarshalBinary(b); err != nil {
		return errgo.Notef(err, "cannot unmarshal macaroon")
	}
	return nil
}

func (m *ussoMacaroon) MarshalJSON() ([]byte, error) {
	data, err := m.Macaroon.MarshalBinary()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	s := base64.RawURLEncoding.EncodeToString(data)
	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return bytes, nil
}
