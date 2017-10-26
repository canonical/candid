// Copyright 2015 Canonical Ltd.

package test

import (
	"net/url"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
)

const authType = "test"

type authInfo struct {
	URL string `json:"url"`
}

type testLoginRequest struct {
	httprequest.Route `httprequest:"POST"`
	User              *params.User `httprequest:",body"`
}

var _ httpbakery.LegacyInteractor = Interactor{}
var _ httpbakery.Interactor = Interactor{}

type Interactor struct {
	// User contains the user to log in as. User may be fully defined
	// in which case the user is added to the database or can be a
	// Username or ExternalID. If the latter two cases the database
	// will be checked for a matching user.
	User *params.User

	// Doer contatins an httprequest.Doer that will be used with
	// OpenWebPage.
	Doer httprequest.Doer
}

// Kind implements httpbakery.Interactor.Kind.
func (i Interactor) Kind() string {
	return authType
}

type testTokenResponse struct {
	DischargeToken *httpbakery.DischargeToken `json:"discharge-token,omitempty"`
}

// Interact implements httpbakery.Interactor.Interact.
func (i Interactor) Interact(ctx context.Context, client *httpbakery.Client, location string, ierr *httpbakery.Error) (*httpbakery.DischargeToken, error) {
	var info authInfo
	if err := ierr.InteractionMethod(authType, &info); err != nil {
		return nil, errgo.Mask(err, errgo.Is(httpbakery.ErrInteractionMethodNotFound))
	}
	cl := &httprequest.Client{
		Doer: client,
	}
	req := &testLoginRequest{
		User: i.User,
	}
	var resp testTokenResponse
	if err := cl.CallURL(ctx, info.URL, req, &resp); err != nil {
		return nil, errgo.Mask(err)
	}

	return resp.DischargeToken, nil
}

// LegacyInteract implements httpbakery.LegacyInteractor.LegacyInteract.
func (i Interactor) LegacyInteract(ctx context.Context, client *httpbakery.Client, location string, u *url.URL) error {
	return errgo.Mask(i.legacyInteract(ctx, client, u.String()))
}

// OpenWebBrowser implements an OpenWebBrowser function for use with
// httpbakery.WebBrowserInteractor.
func (i Interactor) OpenWebBrowser(u *url.URL) error {
	return errgo.Mask(i.legacyInteract(context.Background(), i.Doer, u.String()))
}

func (i Interactor) legacyInteract(ctx context.Context, doer httprequest.Doer, url string) error {
	cl := &httprequest.Client{
		Doer: doer,
	}
	var resp authInfo
	if err := cl.Get(ctx, url, &resp); err != nil {
		return errgo.Mask(err)
	}
	req := &testLoginRequest{
		User: i.User,
	}
	if err := cl.CallURL(ctx, resp.URL, req, nil); err != nil {
		return errgo.Mask(err)
	}
	return nil
}
