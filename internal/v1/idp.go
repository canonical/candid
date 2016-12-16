// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/trace"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

func (h *Handler) newIDPHandler(idp idp.IdentityProvider) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		ctx := context.TODO()
		t := trace.New("identity.internal.v1.idp", idp.Name())
		r.ParseForm()
		st, err := h.storePool.Get()
		if err != nil {
			// TODO(mhilton) consider logging inside the pool.
			t.LazyPrintf("cannot get store: %s", err)
			if errgo.Cause(err) != params.ErrServiceUnavailable {
				t.SetError()
			}
			t.Finish()
			identity.ReqServer.WriteError(ctx, w, errgo.NoteMask(err, "cannot get store", errgo.Any))
			return
		}
		defer func() {
			h.storePool.Put(st)
			t.LazyPrintf("store released")
			t.Finish()
		}()
		ctx = store.ContextWithStore(ctx, st)
		t.LazyPrintf("store acquired")
		// TODO have a pool of these?
		c := &idpHandler{
			h:     h,
			idp:   idp,
			store: st,
			params: httprequest.Params{
				Context:  ctx,
				Response: w,
				Request:  r,
				PathVar:  p,
			},
			place: &place{st.Place},
		}
		idp.Handle(c)
	}
}

// idpHandler provides and idp.Context that is used by identity providers
// to access the identity store.
type idpHandler struct {
	h          *Handler
	store      *store.Store
	idp        idp.IdentityProvider
	params     httprequest.Params
	place      *place
	agentLogin params.AgentLogin
}

// URL implements idp.URLContext.URL.
func (c *idpHandler) URL(path string) string {
	return c.h.location + "/v1/idp/" + c.idp.Name() + path
}

// Params implements idp.Context.Params.
func (c *idpHandler) Params() httprequest.Params {
	return c.params
}

// RequestURL implements idp.Context.RequestURL.
func (c *idpHandler) RequestURL() string {
	return c.h.location + c.params.Request.RequestURI
}

// LoginSuccess implements idp.Context.LoginSuccess.
func (c *idpHandler) LoginSuccess(username params.Username, expiry time.Time) bool {
	c.params.Request.ParseForm()
	waitId := c.params.Request.Form.Get("waitid")
	m, err := c.store.Bakery.Oven.NewMacaroon(
		c.params.Context,
		httpbakery.RequestVersion(c.params.Request),
		expiry,
		[]checkers.Caveat{
			checkers.DeclaredCaveat("username", string(username)),
		},
		bakery.LoginOp,
	)
	if err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot mint identity macaroon"))
		return false
	}
	if waitId != "" {
		if err := c.place.Done(waitId, &loginInfo{
			IdentityMacaroon: macaroon.Slice{m.M()},
		}); err != nil {
			c.LoginFailure(errgo.Notef(err, "cannot complete rendezvous"))
			return false
		}
	}
	c.store.UpdateIdentity(username, bson.D{{"$set", bson.D{{"lastlogin", time.Now()}}}})
	return true
}

// LoginFailure implements idp.Context.LoginFailure.
func (c *idpHandler) LoginFailure(err error) {
	c.params.Request.ParseForm()
	waitId := c.params.Request.Form.Get("waitid")
	_, bakeryErr := httpbakery.ErrorToResponse(c.params.Context, err)
	if waitId != "" {
		c.place.Done(waitId, &loginInfo{
			Error: bakeryErr.(*httpbakery.Error),
		})
	}
	identity.WriteError(c.params.Context, c.params.Response, err)
}

// Bakery implements idp.Context.Bakery.
func (c *idpHandler) Bakery() *bakery.Bakery {
	return c.store.Bakery
}

// Database implements idp.Context.Database.
func (c *idpHandler) Database() *mgo.Database {
	return c.store.DB.Session.DB("idp" + c.idp.Name())
}

// FindUserByExternalId implements idp.Context.FindUserByExternalId.
func (c *idpHandler) FindUserByExternalId(id string) (*params.User, error) {
	var identity mongodoc.Identity
	if err := c.store.DB.Identities().Find(bson.D{{"external_id", id}}).One(&identity); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return nil, errgo.WithCausef(err, params.ErrNotFound, "")
		}
		return nil, errgo.Mask(err)
	}
	return userFromIdentity(c.params.Context, &identity)
}

// FindUserByName implements idp.Context.FindUserByName.
func (c *idpHandler) FindUserByName(name params.Username) (*params.User, error) {
	id, err := c.store.GetIdentity(name)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return userFromIdentity(c.params.Context, id)
}

// UpdateUser implements idp.Context.UpdateUser.
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

// AgentLogin implements agent.agentContext.AgentLogin.
func (c *idpHandler) AgentLogin() params.AgentLogin {
	return c.agentLogin
}

// Store implements agent.agentContext.Store.
func (c *idpHandler) Store() *store.Store {
	return c.store
}
