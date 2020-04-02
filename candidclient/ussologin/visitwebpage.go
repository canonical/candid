// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package ussologin

import (
	"context"
	"net/http"
	"net/url"

	"github.com/juju/usso"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
)

const interactionMethod = "usso_oauth"

type interactionInfo struct {
	URL string `json:"url,omitempty"`
}

// SetInteraction sets the required values for the usso_oauth interaction
// method on an interaction required error.
func SetInteraction(ierr *httpbakery.Error, url string) {
	ierr.SetInteraction(interactionMethod, interactionInfo{
		URL: url,
	})
}

// NewInteractor creates a new httpbakery.Interactor that interacts using
// the usso_oauth protocol.
func NewInteractor(tg TokenGetter) httpbakery.Interactor {
	return &interactor{
		tg: tg,
	}
}

type interactor struct {
	tg TokenGetter
}

// Kind implements httpbakery.Interactor.Kind.
func (*interactor) Kind() string {
	return interactionMethod
}

// Interact implements httpbakery.Interactor.Interact.
func (i *interactor) Interact(ctx context.Context, client *httpbakery.Client, location string, ierr *httpbakery.Error) (*httpbakery.DischargeToken, error) {
	var info interactionInfo
	if err := ierr.InteractionMethod(interactionMethod, &info); err != nil {
		return nil, errgo.Mask(err, errgo.Is(httpbakery.ErrInteractionMethodNotFound))
	}
	var resp LoginResponse
	if err := i.interact(ctx, &httprequest.Client{Doer: client}, info.URL, &resp); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return resp.DischargeToken, nil
}

// LegacyInteract implements httpbakery.LegacyInteractor.LegacyInteract.
func (i *interactor) LegacyInteract(ctx context.Context, client *httpbakery.Client, location string, u *url.URL) error {
	return errgo.Mask(i.interact(ctx, &httprequest.Client{Doer: client}, u.String(), nil), errgo.Any)
}

func (i *interactor) interact(ctx context.Context, client *httprequest.Client, url string, resp interface{}) error {
	tok, err := i.tg.GetToken(ctx)
	if err != nil {
		return errgo.NoteMask(err, "cannot get token", errgo.Any)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errgo.Notef(err, "cannot create request")
	}
	base := *req.URL
	base.RawQuery = ""
	rp := usso.RequestParameters{
		HTTPMethod:      req.Method,
		BaseURL:         base.String(),
		Params:          req.URL.Query(),
		SignatureMethod: usso.HMACSHA1{},
	}
	if err := tok.SignRequest(&rp, req); err != nil {
		return errgo.Notef(err, "cannot sign request")
	}
	if err := client.Do(ctx, req, resp); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// A LoginResponse is a response from the login endpoint following a
// successful interaction.
type LoginResponse struct {
	DischargeToken *httpbakery.DischargeToken `json:"discharge-token"`
}
