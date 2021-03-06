// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package redirect_test

import (
	"context"
	"net/http"
	"testing"

	qt "github.com/frankban/quicktest"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"github.com/canonical/candid/v2/candidclient/redirect"
	"github.com/canonical/candid/v2/params"
)

func TestRedirectURL(t *testing.T) {
	c := qt.New(t)

	info := redirect.InteractionInfo{
		LoginURL: "https://www.example.com/login",
	}
	rurl := info.RedirectURL("https://www.example.com/callback", "12345")
	c.Assert(rurl, qt.Equals, "https://www.example.com/login?return_to=https%3A%2F%2Fwww.example.com%2Fcallback&state=12345")

	info = redirect.InteractionInfo{
		LoginURL: "https://www.example.com/login?domain=test",
	}
	rurl = info.RedirectURL("https://www.example.com/callback", "12345")
	c.Assert(rurl, qt.Equals, "https://www.example.com/login?domain=test&return_to=https%3A%2F%2Fwww.example.com%2Fcallback&state=12345")
}

func TestInteractor(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	var i redirect.Interactor
	c.Assert(i.Kind(), qt.Equals, redirect.Kind)

	req, err := http.NewRequest("GET", "https://www.example.com/discharge", nil)
	c.Assert(err, qt.IsNil)
	irerr := httpbakery.NewInteractionRequiredError(nil, req)
	// Fake an empty InteractionRequiredError
	irerr.Info = &httpbakery.ErrorInfo{}

	_, err = i.Interact(ctx, nil, "", irerr)
	c.Assert(errgo.Cause(err), qt.Equals, httpbakery.ErrInteractionMethodNotFound)

	redirect.SetInteraction(irerr, "https://www.example.com/login", "https://www.example.com/token")

	_, err = i.Interact(ctx, nil, "", irerr)
	c.Assert(err, qt.Satisfies, httpbakery.IsInteractionError)
	ierr := err.(*httpbakery.InteractionError)
	c.Assert(ierr.Reason, qt.Satisfies, redirect.IsRedirectRequiredError)
	c.Assert(ierr.Reason.(*redirect.RedirectRequiredError).InteractionInfo, qt.Equals, redirect.InteractionInfo{
		LoginURL:          "https://www.example.com/login",
		DischargeTokenURL: "https://www.example.com/token",
	})

	dt := &httpbakery.DischargeToken{
		Kind:  "test",
		Value: []byte("test"),
	}
	i.SetDischargeToken("https://www.example.com/login", dt)
	dt2, err := i.Interact(ctx, nil, "", irerr)
	c.Assert(err, qt.IsNil)
	c.Assert(*dt2, qt.DeepEquals, *dt)
}

func TestParseLoginResult(t *testing.T) {
	c := qt.New(t)

	state, code, err := redirect.ParseLoginResult("https://example.com/callback?state=12345&code=54321")
	c.Assert(state, qt.Equals, "12345")
	c.Assert(err, qt.IsNil)
	c.Assert(code, qt.Equals, "54321")

	state, code, err = redirect.ParseLoginResult("https://example.com/callback?state=12345&error_code=ec&error=test+error")
	c.Assert(state, qt.Equals, "12345")
	c.Assert(errgo.Cause(err), qt.Equals, params.ErrorCode("ec"))
	c.Assert(err, qt.ErrorMatches, "test error")
	c.Assert(code, qt.Equals, "")

	state, code, err = redirect.ParseLoginResult("https://example.com/callback?state=12345&error=test+error")
	c.Assert(state, qt.Equals, "12345")
	c.Assert(err, qt.ErrorMatches, "test error")
	c.Assert(code, qt.Equals, "")
}
