// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package httpauth

import (
	"context"
	"net/http"
	"time"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery/checkers"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery/identchecker"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery"
	errgo "gopkg.in/errgo.v1"

	"github.com/canonical/candid/internal/auth"
	"github.com/canonical/candid/params"
)

// An Authorizer is used to authorize HTTP requests.
type Authorizer struct {
	authorizer *auth.Authorizer
	oven       *bakery.Oven
	timeout    time.Duration
}

// New creates a new Authorizer for authorizing HTTP requests made to the
// identity server. The given oven is used to make new macaroons; the
// given authorizer is used as the underlying authorizer.
func New(o *bakery.Oven, a *auth.Authorizer, timeout time.Duration) *Authorizer {
	return &Authorizer{
		authorizer: a,
		oven:       o,
		timeout:    timeout,
	}
}

// Auth checks that client making the given request is authorized to
// perform the given operations. It may return an httpbakery error when
// further checks are required, or params.ErrUnauthorized if the user is
// authenticated but does not have the required authorization.
func (a *Authorizer) Auth(ctx context.Context, req *http.Request, ops ...bakery.Op) (*identchecker.AuthInfo, error) {
	ctx = httpbakery.ContextWithRequest(ctx, req)
	if username, password, ok := req.BasicAuth(); ok {
		ctx = auth.ContextWithUserCredentials(ctx, username, password)
	}
	authInfo, err := a.authorizer.Auth(ctx, httpbakery.RequestMacaroons(req), ops...)
	if err == nil {
		return authInfo, nil
	}
	derr, ok := errgo.Cause(err).(*bakery.DischargeRequiredError)
	if !ok {
		return nil, errgo.Mask(err, errgo.Is(params.ErrUnauthorized))
	}
	caveats := append(derr.Caveats, checkers.TimeBeforeCaveat(time.Now().Add(a.timeout)))
	m, err := a.oven.NewMacaroon(
		ctx,
		httpbakery.RequestVersion(req),
		caveats,
		derr.Ops...,
	)
	if err != nil {
		return nil, errgo.Notef(err, "cannot create macaroon")
	}
	return nil, httpbakery.NewDischargeRequiredError(httpbakery.DischargeRequiredErrorParams{
		Macaroon:         m,
		Request:          req,
		OriginalError:    derr,
		CookieNameSuffix: "candid",
	})
}
