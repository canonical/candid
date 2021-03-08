// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"context"
	"encoding/json"

	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"gopkg.in/canonical/candid.v2/meeting"
	"gopkg.in/canonical/candid.v2/store"
)

type dischargeRequestInfo struct {
	CaveatId  []byte
	Caveat    []byte
	Condition string
	Origin    string
}

type loginInfo struct {
	// When a user logs in successfully their ProviderID will be supplied.
	ProviderID store.ProviderIdentity

	// When a login request fails, the error is filled out appropriately.
	Error *httpbakery.Error
}

// place layers our desired types onto the general meeting.Place,
type place struct {
	place *meeting.Place
}

func (p *place) NewRendezvous(ctx context.Context, id string, info *dischargeRequestInfo) error {
	reqData, err := json.Marshal(info)
	if err != nil {
		return errgo.Notef(err, "cannot marshal reqData")
	}
	return p.place.NewRendezvous(ctx, id, reqData)
}

func (p *place) Done(ctx context.Context, id string, info *loginInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return errgo.Notef(err, "cannot marshal loginData")
	}
	return p.place.Done(ctx, id, data)
}

func (p *place) Wait(ctx context.Context, id string) (*dischargeRequestInfo, *loginInfo, error) {
	reqData, loginData, err := p.place.Wait(ctx, id)
	if err != nil {
		return nil, nil, errgo.Notef(err, "cannot wait")
	}
	var info dischargeRequestInfo
	if err := json.Unmarshal(reqData, &info); err != nil {
		return nil, nil, errgo.Notef(err, "cannot unmarshal reqData")
	}
	var login loginInfo
	if err := json.Unmarshal(loginData, &login); err != nil {
		return nil, nil, errgo.Notef(err, "cannot unmarshal loginData")
	}
	return &info, &login, nil
}
