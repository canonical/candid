// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

// Package ussomacaroon provides a client that can authenticate with an
// identity server by discharging macaroons on an Ubuntu SSO server.
package ussodischarge

import (
	"context"
	stdurl "net/url"

	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v3/bakery"
	"gopkg.in/macaroon-bakery.v3/httpbakery"
	"gopkg.in/macaroon.v2"
)

const protocolName = "usso_macaroon"

// Macaroon returns a macaroon from the identity provider at the given
// URL that can be discharged using a Discharger. If doer is non-nil
// then it will be used to collect the macaroon.
func Macaroon(ctx context.Context, doer httprequest.Doer, url string) (*bakery.Macaroon, error) {
	client := &httprequest.Client{
		Doer: doer,
	}
	var resp MacaroonResponse
	if err := client.Get(ctx, url, &resp); err != nil {
		return nil, errgo.Notef(err, "cannot get macaroon")
	}
	return resp.Macaroon, nil
}

type interactionInfo struct {
	URL string `json:"url"`
}

func SetInteraction(ierr *httpbakery.Error, url string) {
	ierr.SetInteraction(protocolName, interactionInfo{URL: url})
}

// Interactor is an httpbakery.Interactor that will login using a
// macaroon discharged by an Ubuntu SSO service.
type Interactor struct {
	f func(*httpbakery.Client, string) (macaroon.Slice, error)
}

// NewInteractor creates an Interactor which uses a macaroon previously
// collected with Macaroon and discharged by the requisit Ubuntu SSO
// service to log in. The discharged macaroon to use will be requested
// from the given function when required.
func NewInteractor(f func(client *httpbakery.Client, url string) (macaroon.Slice, error)) *Interactor {
	return &Interactor{
		f: f,
	}
}

func (i *Interactor) Kind() string {
	return protocolName
}

func (i *Interactor) Interact(ctx context.Context, client *httpbakery.Client, location string, ierr *httpbakery.Error) (*httpbakery.DischargeToken, error) {
	var info interactionInfo
	if err := ierr.InteractionMethod(protocolName, &info); err != nil {
		return nil, errgo.Mask(err, errgo.Is(httpbakery.ErrInteractionMethodNotFound))
	}
	ms, err := i.f(client, info.URL)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	cl := httprequest.Client{
		Doer: client,
	}
	var resp LoginResponse
	err = cl.CallURL(ctx, info.URL, &LoginRequest{
		Login: Login{
			Macaroons: ms,
		},
	}, &resp)
	return resp.DischargeToken, errgo.Mask(err)
}

// LegacyInteract implements httpbakery.LegacyInteractor
// for the Interactor.
func (i *Interactor) LegacyInteract(ctx context.Context, client *httpbakery.Client, location string, visitURL *stdurl.URL) error {
	ms, err := i.f(client, visitURL.String())
	if err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	cl := httprequest.Client{
		Doer: client,
	}
	err = cl.CallURL(ctx, visitURL.String(), &LoginRequest{
		Login: Login{
			Macaroons: ms,
		},
	}, nil)
	return errgo.Mask(err)
}

// Discharger is a client that can discharge Ubuntu SSO third-party
// caveats.
type Discharger struct {
	// Email contains the email address of the user.
	Email string

	// Password contains the password of the user.
	Password string

	// OTP contains the verification code of the user.
	OTP string

	// Doer will be used to perform the discharge if non-nil.
	Doer httprequest.Doer
}

// AcquireDischarge discharges the given Ubuntu SSO third-party caveat using the
// user information from the Discharger.
func (d *Discharger) AcquireDischarge(ctx context.Context, cav macaroon.Caveat, payload []byte) (*bakery.Macaroon, error) {
	if len(payload) > 0 {
		return nil, errgo.Newf("USSO does not support macaroon-external third party caveats")
	}
	client := httprequest.Client{
		BaseURL: cav.Location,
		Doer:    d.Doer,
	}
	req := &ussoDischargeRequest{
		Discharge: ussoDischarge{
			Email:    d.Email,
			Password: d.Password,
			OTP:      d.OTP,
			CaveatID: string(cav.Id),
		},
	}
	var resp ussoDischargeResponse
	if err := client.Call(ctx, req, &resp); err != nil {
		return nil, errgo.Mask(err)
	}
	return bakery.NewLegacyMacaroon(&resp.Macaroon.Macaroon)
}

// DischargeAll discharges the given macaroon which is assumed to only
// have third-party caveats addressed to an Ubuntu SSO server.
func (d *Discharger) DischargeAll(ctx context.Context, m *bakery.Macaroon) (macaroon.Slice, error) {
	ms, err := bakery.DischargeAll(ctx, m, d.AcquireDischarge)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return ms, nil
}
