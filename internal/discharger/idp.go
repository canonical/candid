// Copyright 2014 Canonical Ltd.

package discharger

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juju/idmclient"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	macaroon "gopkg.in/macaroon.v2-unstable"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/store"
)

const (
	// identityMacaroonDuration is the length of time for which an
	// identity macaroon is valid.
	identityMacaroonDuration = 28 * 24 * time.Hour
)

func initIDPs(ctx context.Context, params identity.HandlerParams, lc *loginCompleter) error {
	for _, ip := range params.IdentityProviders {
		if err := ip.Init(ctx, idp.InitParams{
			Store:          params.Store,
			URLPrefix:      params.Location + "/login/" + ip.Name(),
			LoginCompleter: lc,
			Template:       params.Template,
			Key:            params.Key,
		}); err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

func newIDPHandler(params identity.HandlerParams, idp idp.IdentityProvider) httprouter.Handle {
	pathPrefix := ""
	u, err := url.Parse(params.Location)
	if err != nil {
		logger.Warningf("location %q does not parse as a URL: %s", params.Location, err)
		// if the location doesn't parse as a URL just assume the path has no prefix.
	} else if u.Path != "/" {
		pathPrefix = u.Path
	}
	return func(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
		t := trace.New("identity.internal.v1.idp", idp.Name())
		defer t.Finish()
		ctx := trace.NewContext(context.Background(), t)
		ctx, close := params.Store.Context(ctx)
		defer close()
		ctx, close = params.MeetingStore.Context(ctx)
		defer close()
		req.URL.Path = strings.TrimPrefix(req.URL.Path, pathPrefix+"/login/"+idp.Name())
		req.ParseForm()
		idp.Handle(ctx, w, req)
	}
}

// A loginCompleter is an implementation of idp.LoginCompleter.
type loginCompleter struct {
	params identity.HandlerParams
	place  *place
}

// Success implements idp.LoginCompleter.Success.
func (c *loginCompleter) Success(ctx context.Context, w http.ResponseWriter, req *http.Request, waitid string, id *store.Identity) {
	logger.Infof("login success, username %q", id.Username)
	err := c.complete(
		ctx,
		waitid,
		httpbakery.RequestVersion(req),
		id.Username,
		time.Now().Add(identityMacaroonDuration),
	)
	if err != nil {
		c.Failure(ctx, w, req, waitid, errgo.Mask(err))
		return
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

// completeLogin finishes a login attempt. A new macaroon will be minted
// with the given version, username and expiry and used to complete the
// rendezvous specified by the given waitid.
func (c *loginCompleter) complete(ctx context.Context, waitid string, v bakery.Version, username string, expiry time.Time) error {
	m, err := c.params.Oven.NewMacaroon(
		ctx,
		v,
		expiry,
		[]checkers.Caveat{
			idmclient.UserDeclaration(username),
		},
		bakery.LoginOp,
	)
	if err != nil {
		return errgo.Notef(err, "cannot mint identity macaroon")
	}
	if waitid != "" {
		if err := c.place.Done(ctx, waitid, &loginInfo{
			IdentityMacaroon: macaroon.Slice{m.M()},
		}); err != nil {
			return errgo.Notef(err, "cannot complete rendezvous")
		}
	}
	c.params.Store.UpdateIdentity(ctx, &store.Identity{
		Username:  username,
		LastLogin: time.Now(),
	}, store.Update{
		store.LastLogin: store.Set,
	})
	return nil
}

// Failure implements idp.LoginCompleter.Failure.
func (c *loginCompleter) Failure(ctx context.Context, w http.ResponseWriter, req *http.Request, waitid string, err error) {
	_, bakeryErr := httpbakery.ErrorToResponse(ctx, err)
	if waitid != "" {
		c.place.Done(ctx, waitid, &loginInfo{
			Error: bakeryErr.(*httpbakery.Error),
		})
	}
	identity.WriteError(ctx, w, err)
}
