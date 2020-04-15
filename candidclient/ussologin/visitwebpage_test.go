// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package ussologin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/usso"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/canonical/candid/candidclient/ussologin"
)

func TestKind(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	i := ussologin.NewInteractor(nil)
	c.Assert(i.Kind(), qt.Equals, "usso_oauth")
}

func TestInteractNotSupportedError(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	i := ussologin.NewInteractor(nil)
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	ierr := httpbakery.NewInteractionRequiredError(nil, req)
	httpbakery.SetLegacyInteraction(ierr, "", "")
	_, err = i.Interact(context.Background(), nil, "", ierr)
	c.Assert(errgo.Cause(err), qt.Equals, httpbakery.ErrInteractionMethodNotFound)
}

func TestInteractGetTokenError(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	terr := errgo.New("test error")
	i := ussologin.NewInteractor(tokenGetterFunc(func(_ context.Context) (*usso.SSOData, error) {
		return nil, terr
	}))
	ierr := interactionRequiredError(c, "")
	_, err := i.Interact(context.Background(), nil, "", ierr)
	c.Assert(errgo.Cause(err), qt.Equals, terr)
}

func TestAuthenticatedRequest(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Just check the request has a correct looking
		// Authorization header, we won't check the signature.
		c.Check(req.Header.Get("Authorization"), qt.Matches, "OAuth .*")
		httprequest.WriteJSON(w, http.StatusOK, ussologin.LoginResponse{
			DischargeToken: &httpbakery.DischargeToken{
				Kind:  "test",
				Value: []byte("test-token"),
			},
		})
	}))
	defer server.Close()

	i := ussologin.NewInteractor(tokenGetterFunc(func(_ context.Context) (*usso.SSOData, error) {
		return &usso.SSOData{
			ConsumerKey:    "test-user",
			ConsumerSecret: "test-user-secret",
			Realm:          "test",
			TokenKey:       "test-token",
			TokenName:      "test",
			TokenSecret:    "test-token-secret",
		}, nil
	}))
	ierr := interactionRequiredError(c, server.URL)
	dt, err := i.Interact(context.Background(), httpbakery.NewClient(), "", ierr)
	c.Assert(err, qt.IsNil)
	c.Assert(dt, qt.DeepEquals, &httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte("test-token"),
	})
}

func TestAuthenticatedRequestError(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Just check the request has a correct looking
		// Authorization header, we won't check the signature.
		c.Check(req.Header.Get("Authorization"), qt.Matches, "OAuth .*")
		code, body := httpbakery.ErrorToResponse(context.Background(), errgo.New("test error"))
		httprequest.WriteJSON(w, code, body)
	}))
	defer server.Close()

	i := ussologin.NewInteractor(tokenGetterFunc(func(_ context.Context) (*usso.SSOData, error) {
		return &usso.SSOData{
			ConsumerKey:    "test-user",
			ConsumerSecret: "test-user-secret",
			Realm:          "test",
			TokenKey:       "test-token",
			TokenName:      "test",
			TokenSecret:    "test-token-secret",
		}, nil
	}))
	ierr := interactionRequiredError(c, server.URL)
	_, err := i.Interact(context.Background(), httpbakery.NewClient(), "", ierr)
	c.Assert(err, qt.ErrorMatches, `Get http.*: test error`)
}

func interactionRequiredError(c *qt.C, url string) *httpbakery.Error {
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, qt.IsNil)
	ierr := httpbakery.NewInteractionRequiredError(nil, req)
	ussologin.SetInteraction(ierr, url)
	return ierr
}

type tokenGetterFunc func(ctx context.Context) (*usso.SSOData, error)

func (f tokenGetterFunc) GetToken(ctx context.Context) (*usso.SSOData, error) {
	return f(ctx)
}
