// Copyright 2014 Canonical Ltd.

package v1

import (
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/juju/idmclient/params"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
)

func (h *Handler) initIDPs() error {
	ctx := context.TODO()
	hnd, ctx, err := h.getHandler(ctx, nil)
	if err != nil {
		return errgo.Mask(err)
	}
	defer hnd.Close()
	for _, idp := range h.idps {
		ctx := &idpHandler{
			Context: ctx,
			handler: hnd,
			idp:     idp,
		}
		if err := idp.Init(ctx); err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

func (h *Handler) newIDPHandler(idp idp.IdentityProvider) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
		ctx := context.TODO()
		t := trace.New("identity.internal.v1.idp", idp.Name())
		ctx = trace.NewContext(ctx, t)
		hnd, ctx, err := h.getHandler(ctx, t)
		if err != nil {
			t.Finish()
			identity.ReqServer.WriteError(ctx, w, errgo.NoteMask(err, "cannot get store", errgo.Any))
		}
		defer hnd.Close()
		// TODO have a pool of these?
		c := &idpHandler{
			Context:        ctx,
			handler:        hnd,
			idp:            idp,
			responseWriter: w,
			request:        req,
		}
		req.ParseForm()
		idp.Handle(c, w, req)
	}
}

// idpHandler provides and idp.Context that is used by identity providers
// to access the identity store.
type idpHandler struct {
	context.Context
	*handler
	idp            idp.IdentityProvider
	responseWriter http.ResponseWriter
	request        *http.Request
}

// URL implements idp.Context.URL.
func (c *idpHandler) URL(path string) string {
	return c.serviceURL("/v1/idp/" + c.idp.Name() + path)
}

// RequestURL implements idp.RequestContext.RequestURL.
func (c *idpHandler) RequestURL() string {
	return c.serviceURL(c.request.RequestURI)
}

// Path implements idp.RequestContext.Path.
func (c *idpHandler) Path() string {
	return strings.TrimPrefix(c.request.URL.Path, "/v1/idp/"+c.idp.Name())
}

// LoginSuccess implements idp.RequestContext.LoginSuccess.
func (c *idpHandler) LoginSuccess(waitid string, username params.Username, expiry time.Time) bool {
	logger.Infof("login success, username %q", username)
	if err := c.completeLogin(c, waitid, httpbakery.RequestVersion(c.request), username, expiry); err != nil {
		c.LoginFailure(waitid, errgo.Mask(err))
		return false
	}
	return true
}

// LoginFailure implements idp.RequestContext.LoginFailure.
func (c *idpHandler) LoginFailure(waitid string, err error) {
	_, bakeryErr := httpbakery.ErrorToResponse(c, err)
	if waitid != "" {
		c.place.Done(waitid, &loginInfo{
			Error: bakeryErr.(*httpbakery.Error),
		})
	}
	identity.WriteError(c, c.responseWriter, err)
}

// Key implements idp.Context.Key.
func (c *idpHandler) Key() *bakery.KeyPair {
	return c.h.key
}

// Bakery implements idp.RequestContext.Bakery.
func (c *idpHandler) Bakery() *bakery.Bakery {
	return c.store.Bakery
}

// Template implements idp.RequestContext.Template.
func (c *idpHandler) Template(name string) *template.Template {
	return c.h.template.Lookup(name)
}

// Database implements idp.Context.Database.
func (c *idpHandler) Database() *mgo.Database {
	return c.store.DB.Session.DB("idp" + c.idp.Name())
}

// FindUserByExternalId implements idp.RequestContext.FindUserByExternalId.
func (c *idpHandler) FindUserByExternalId(id string) (*params.User, error) {
	var identity mongodoc.Identity
	if err := c.store.DB.Identities().Find(bson.D{{"external_id", id}}).One(&identity); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return nil, errgo.WithCausef(err, params.ErrNotFound, "")
		}
		return nil, errgo.Mask(err)
	}
	return userFromIdentity(c, &identity)
}

// FindUserByName implements idp.RequestContext.FindUserByName.
func (c *idpHandler) FindUserByName(name params.Username) (*params.User, error) {
	id, err := c.store.GetIdentity(name)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return userFromIdentity(c, id)
}

// UpdateUser implements idp.RequestContext.UpdateUser.
func (c *idpHandler) UpdateUser(u *params.User) error {
	id := identityFromUser(u)
	if id.Owner != "" {
		if err := c.store.UpsertAgent(id); err != nil {
			return errgo.Mask(err)
		}
		return nil
	}
	if err := c.store.UpsertUser(id); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrAlreadyExists))
	}
	return nil
}
