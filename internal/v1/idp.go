// Copyright 2014 Canonical Ltd.

package v1

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/juju/idmclient/params"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/store"
)

const (
	// identityMacaroonDuration is the length of time for which an
	// identity macaroon is valid.
	identityMacaroonDuration = 28 * 24 * time.Hour
)

func (h *Handler) initIDPs(ctx context.Context) error {
	for _, ip := range h.idps {
		if err := ip.Init(ctx, idp.InitParams{
			Store:          h.store,
			URLPrefix:      h.serviceURL("/v1/idp/" + ip.Name()),
			LoginCompleter: loginCompleter{h},
			Template:       h.template,
			Key:            h.oven.Key(),
		}); err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

func (h *Handler) newIDPHandler(idp idp.IdentityProvider) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
		t := trace.New("identity.internal.v1.idp", idp.Name())
		defer t.Finish()
		ctx := trace.NewContext(context.Background(), t)
		ctx, close := h.store.Context(ctx)
		defer close()
		ctx, close = h.meetingStore.Context(ctx)
		defer close()
		req.URL.Path = strings.TrimPrefix(req.URL.Path, "/v1/idp/"+idp.Name())
		req.ParseForm()
		idp.Handle(ctx, w, req)
	}
}

type loginCompleter struct {
	h *Handler
}

// Success implements idp.LoginCompleter.Success.
func (c loginCompleter) Success(ctx context.Context, w http.ResponseWriter, req *http.Request, waitid string, id *store.Identity) {
	logger.Infof("login success, username %q", id.Username)
	err := c.h.completeLogin(
		ctx,
		waitid,
		httpbakery.RequestVersion(req),
		params.Username(id.Username),
		time.Now().Add(identityMacaroonDuration),
	)
	if err != nil {
		c.Failure(ctx, w, req, waitid, errgo.Mask(err))
		return
	}
	t := c.h.template.Lookup("login")
	if t == nil {
		fmt.Fprintf(w, "Login successful as %s", id.Username)
		return
	}
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	if err := t.Execute(w, id); err != nil {
		logger.Errorf("error processing login template: %s", err)
	}
}

// Failure implements idp.LoginCompleter.Failure.
func (c loginCompleter) Failure(ctx context.Context, w http.ResponseWriter, req *http.Request, waitid string, err error) {
	_, bakeryErr := httpbakery.ErrorToResponse(ctx, err)
	if waitid != "" {
		c.h.place.Done(ctx, waitid, &loginInfo{
			Error: bakeryErr.(*httpbakery.Error),
		})
	}
	identity.WriteError(ctx, w, err)
}
