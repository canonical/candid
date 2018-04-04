// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/idmclient.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/auth"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/store"
)

const (
	// identityMacaroonDuration is the length of time for which an
	// identity macaroon is valid.
	identityMacaroonDuration = 28 * 24 * time.Hour

	// dischargeTokenDuration is the length of time for which a
	// discharge token is valid.
	dischargeTokenDuration = 10 * time.Minute
)

func initIDPs(ctx context.Context, params identity.HandlerParams, dt *dischargeTokenCreator, vc *visitCompleter) error {
	for _, ip := range params.IdentityProviders {
		kvStore, err := params.ProviderDataStore.KeyValueStore(ctx, ip.Name())
		if err != nil {
			return errgo.Mask(err)
		}
		if err := ip.Init(ctx, idp.InitParams{
			Store:                 params.Store,
			KeyValueStore:         kvStore,
			URLPrefix:             params.Location + "/login/" + ip.Name(),
			DischargeTokenCreator: dt,
			VisitCompleter:        vc,
			Template:              params.Template,
			Key:                   params.Key,
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

func (d *dischargeTokenCreator) DischargeToken(ctx context.Context, dischargeID string, id *store.Identity) (*httpbakery.DischargeToken, error) {
	cavs := []checkers.Caveat{
		idmclient.UserDeclaration(id.Username),
	}
	if dischargeID != "" {
		cavs = append(cavs, auth.DischargeIDCaveat(dischargeID))
	}
	cavs = append(cavs, checkers.TimeBeforeCaveat(time.Now().Add(dischargeTokenDuration)))
	m, err := d.params.Oven.NewMacaroon(
		ctx,
		bakery.LatestVersion,
		cavs,
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
	params                identity.HandlerParams
	dischargeTokenCreator *dischargeTokenCreator
	place                 *place
}

// Success implements idp.VisitCompleter.Success.
func (c *visitCompleter) Success(ctx context.Context, w http.ResponseWriter, req *http.Request, dischargeID string, id *store.Identity) {
	dt, err := c.dischargeTokenCreator.DischargeToken(ctx, dischargeID, id)
	if err != nil {
		c.Failure(ctx, w, req, dischargeID, errgo.Mask(err))
		return
	}
	if dischargeID != "" {
		if err := c.place.Done(ctx, dischargeID, &loginInfo{DischargeToken: dt}); err != nil {
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
