// Copyright 2014 Canonical Ltd.

package v1

import (
	"encoding/json"
	"fmt"

	"gopkg.in/macaroon-bakery.v0/httpbakery"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/meeting"
)

type thirdPartyCaveatInfo struct {
	CaveatId string
	Caveat   string
}

type loginInfo struct {
	// When a user logs in successfully, an identity
	// macaroon is provided which grants them
	// the right to perform operations as that user.
	IdentityMacaroon *macaroon.Macaroon

	// When a login request fails, the error is filled out appropriately.
	Error *httpbakery.Error
}

// place layers our desired types onto the general meeting.Place,
type place struct {
	place *meeting.Place
}

func (p *place) NewRendezvous(info *thirdPartyCaveatInfo) (string, error) {
	reqData, err := json.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("cannot marshal reqData: %v", err)
	}
	return p.place.NewRendezvous(reqData)
}

func (p *place) Done(waitId string, info *loginInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("cannot marshal loginData: %v", err)
	}
	return p.place.Done(waitId, data)
}

func (p *place) Wait(waitId string) (*thirdPartyCaveatInfo, *loginInfo, error) {
	reqData, loginData, err := p.place.Wait(waitId)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot wait: %v", err)
	}
	var caveat thirdPartyCaveatInfo
	if err := json.Unmarshal(reqData, &caveat); err != nil {
		return nil, nil, fmt.Errorf("cannot unmarshal reqData: %v", err)
	}
	var login loginInfo
	if err := json.Unmarshal(loginData, &login); err != nil {
		return nil, nil, fmt.Errorf("cannot unmarshal loginData: %v", err)
	}
	return &caveat, &login, nil
}
