// Copyright 2014 Canonical Ltd.

package v1

import (
	"encoding/json"
	"fmt"

	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"

	"github.com/CanonicalLtd/blues-identity/meeting"
)

type dischargeRequestInfo struct {
	CaveatId  []byte
	Caveat    []byte
	Condition string
	Origin    string
}

type loginInfo struct {
	// When a user logs in successfully, an identity
	// macaroon is provided which grants them
	// the right to perform operations as that user.
	IdentityMacaroon macaroon.Slice

	// When a login request fails, the error is filled out appropriately.
	Error *httpbakery.Error
}

// place layers our desired types onto the general meeting.Place,
type place struct {
	place *meeting.Place
}

func (p *place) NewRendezvous(info *dischargeRequestInfo) (string, error) {
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

func (p *place) Wait(waitId string) (*dischargeRequestInfo, *loginInfo, error) {
	reqData, loginData, err := p.place.Wait(waitId)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot wait: %v", err)
	}
	var info dischargeRequestInfo
	if err := json.Unmarshal(reqData, &info); err != nil {
		return nil, nil, fmt.Errorf("cannot unmarshal reqData: %v", err)
	}
	var login loginInfo
	if err := json.Unmarshal(loginData, &login); err != nil {
		return nil, nil, fmt.Errorf("cannot unmarshal loginData: %v", err)
	}
	return &info, &login, nil
}
