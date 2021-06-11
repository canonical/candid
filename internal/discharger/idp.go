// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/trace"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/canonical/candid/candidclient"
	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/idputil/secret"
	"github.com/canonical/candid/internal/auth"
	"github.com/canonical/candid/internal/discharger/internal"
	"github.com/canonical/candid/internal/identity"
	"github.com/canonical/candid/params"
	"github.com/canonical/candid/store"
)

type initIDPParams struct {
	identity.HandlerParams
	Codec                 *secret.Codec
	DischargeTokenCreator *dischargeTokenCreator
	VisitCompleter        *visitCompleter
}

func initIDPs(ctx context.Context, params initIDPParams) error {
	for _, ip := range params.IdentityProviders {
		kvStore, err := params.ProviderDataStore.KeyValueStore(ctx, ip.Name())
		if err != nil {
			return errgo.Mask(err)
		}
		if err := ip.Init(ctx, idp.InitParams{
			Store:                      params.Store,
			KeyValueStore:              kvStore,
			Oven:                       params.Oven,
			Codec:                      params.Codec,
			Location:                   params.Location,
			URLPrefix:                  params.Location + "/login/" + ip.Name(),
			DischargeTokenCreator:      params.DischargeTokenCreator,
			VisitCompleter:             params.VisitCompleter,
			Template:                   params.Template,
			SkipLocationForCookiePaths: params.SkipLocationForCookiePaths,
		}); err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

func newIDPHandler(params identity.HandlerParams, idp idp.IdentityProvider) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
		t := trace.New("identity.internal.v1.idp", idp.Name())
		defer t.Finish()
		ctx := trace.NewContext(context.Background(), t)
		ctx, close := params.Store.Context(ctx)
		defer close()
		ctx, close = params.MeetingStore.Context(ctx)
		defer close()
		req.URL.Path = strings.TrimPrefix(req.URL.Path, "/login/"+idp.Name())
		req.ParseForm()
		idp.Handle(ctx, w, req)
	}
}

type dischargeTokenCreator struct {
	params identity.HandlerParams
}

func (d *dischargeTokenCreator) DischargeToken(ctx context.Context, id *store.Identity) (*httpbakery.DischargeToken, error) {
	m, err := d.params.Oven.NewMacaroon(
		ctx,
		bakery.LatestVersion,
		[]checkers.Caveat{
			checkers.TimeBeforeCaveat(time.Now().Add(d.params.DischargeTokenTimeout)),
			candidclient.UserIDDeclaration(string(id.ProviderID)),
		},
		identchecker.LoginOp,
	)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	v, err := m.M().MarshalBinary()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	id.LastLogin = time.Now()
	if err := d.params.Store.UpdateIdentity(ctx, id, store.Update{
		store.LastLogin: store.Set,
	}); err != nil {
		logger.Errorf("cannot update last login time: %s", err)
	}
	return &httpbakery.DischargeToken{
		Kind:  "macaroon",
		Value: v,
	}, nil
}

// A visitCompleter is an implementation of idp.VisitCompleter.
type visitCompleter struct {
	params        identity.HandlerParams
	identityStore *internal.IdentityStore
	place         *place
}

// Success implements idp.VisitCompleter.Success.
func (c *visitCompleter) Success(ctx context.Context, w http.ResponseWriter, req *http.Request, dischargeID string, id *store.Identity) {
	if dischargeID != "" {
		if err := c.place.Done(ctx, dischargeID, &loginInfo{ProviderID: id.ProviderID}); err != nil {
			c.Failure(ctx, w, req, dischargeID, errgo.Mask(err))
			return
		}
	}

	t := c.params.Template.Lookup("login")
	if t == nil {
		fmt.Fprintf(w, "Login successful as %s", id.Username)
		return
	}
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	if err := t.Execute(w, id); err != nil {
		logger.Errorf("error processing login template: %s", err)
	}
}

// Failure implements idp.VisitCompleter.Failure.
func (c *visitCompleter) Failure(ctx context.Context, w http.ResponseWriter, req *http.Request, dischargeID string, err error) {
	_, bakeryErr := httpbakery.ErrorToResponse(ctx, err)
	if dischargeID != "" {
		c.place.Done(ctx, dischargeID, &loginInfo{
			Error: bakeryErr.(*httpbakery.Error),
		})
	}
	identity.WriteError(ctx, w, err)
}

// RedirectSuccess implements idp.VisitCompleter.RedirectSuccess.
func (c *visitCompleter) RedirectSuccess(ctx context.Context, w http.ResponseWriter, req *http.Request, returnTo, state string, id *store.Identity) {
	code, err := c.identityStore.Put(ctx, id, time.Now().Add(10*time.Minute))
	if err != nil {
		c.RedirectFailure(ctx, w, req, returnTo, state, errgo.Mask(err))
		return
	}
	v := url.Values{
		"code": {code},
	}
	if state != "" {
		v.Set("state", state)
	}
	if err := c.redirect(w, req, returnTo, v); err != nil {
		identity.WriteError(ctx, w, err)
	}
	return
}

// RedirectFailure implements idp.VisitCompleter.RedirectFailure.
func (c *visitCompleter) RedirectFailure(ctx context.Context, w http.ResponseWriter, req *http.Request, returnTo, state string, err error) {
	v := url.Values{
		"error": {err.Error()},
	}
	if state != "" {
		v.Set("state", state)
	}
	if ec, ok := errgo.Cause(err).(params.ErrorCode); ok {
		v.Set("error_code", string(ec))
	}
	if rerr := c.redirect(w, req, returnTo, v); rerr == nil {
		return
	}
	identity.WriteError(ctx, w, err)
}

// redirect writes a redirect response addressed the the given returnTo
// address with the given query parameters. If an error is returned it
// will be because the returnTo address is invalid and therefore it will
// not be possible to redirect to it.
func (c *visitCompleter) redirect(w http.ResponseWriter, req *http.Request, returnTo string, query url.Values) error {
	// Check the return to is a valid URL and is an allowed address.
	u, err := url.Parse(returnTo)
	if err != nil || !c.isValidReturnTo(u) {
		return errgo.WithCausef(err, params.ErrBadRequest, "invalid return_to")
	}

	q := u.Query()
	for k, v := range query {
		q[k] = append(q[k], v...)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, req, u.String(), http.StatusSeeOther)
	return nil
}

func (c *visitCompleter) isValidReturnTo(u *url.URL) bool {
	s := u.String()
	if s == c.params.Location+"/login-complete" {
		return true
	}
	for _, rurl := range c.params.RedirectLoginTrustedURLs {
		if s == rurl {
			return true
		}
	}
	if u.Scheme != "https" {
		return false
	}
	for _, d := range c.params.RedirectLoginTrustedDomains {
		if strings.HasPrefix(d, "*.") && strings.HasSuffix(u.Host, d[1:]) {
			return true
		} else if u.Host == d {
			return true
		}
	}
	return false
}

func usernameFromDischargeToken(dt *httpbakery.DischargeToken) string {
	if dt.Kind != "macaroon" {
		return ""
	}
	var m macaroon.Macaroon
	if err := m.UnmarshalBinary(dt.Value); err != nil {
		return ""
	}
	return checkers.InferDeclared(auth.Namespace, macaroon.Slice{&m})["username"]
}
