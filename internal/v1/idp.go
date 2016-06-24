// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"

	"golang.org/x/net/trace"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
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
		t := trace.New("identity.internal.v1.idp", idp.Name())
		r.ParseForm()
		store, err := h.storePool.Get()
		if err != nil {
			// TODO(mhilton) consider logging inside the pool.
			t.LazyPrintf("cannot get store: %s", err)
			if errgo.Cause(err) != params.ErrServiceUnavailable {
				t.SetError()
			}
			t.Finish()
			identity.ErrorMapper.WriteError(w, errgo.NoteMask(err, "cannot get store", errgo.Any))
			return
		}
		defer func() {
			h.storePool.Put(store)
			t.LazyPrintf("store released")
			t.Finish()
		}()
		t.LazyPrintf("store acquired")
		// TODO have a pool of these?
		c := &idpHandler{
			h:     h,
			idp:   idp,
			store: store,
			params: httprequest.Params{
				Response: w,
				Request:  r,
				PathVar:  p,
			},
			place: &place{store.Place},
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
func (c *idpHandler) LoginSuccess(ms macaroon.Slice) bool {
	c.params.Request.ParseForm()
	waitId := c.params.Request.Form.Get("waitid")
	if waitId != "" {
		if err := c.place.Done(waitId, &loginInfo{
			IdentityMacaroon: ms,
		}); err != nil {
			c.LoginFailure(errgo.Notef(err, "cannot complete rendezvous"))
			return false
		}
	}
	return true
}

// LoginFailure implements idp.Context.LoginFailure.
func (c *idpHandler) LoginFailure(err error) {
	c.params.Request.ParseForm()
	waitId := c.params.Request.Form.Get("waitid")
	_, bakeryErr := httpbakery.ErrorToResponse(err)
	if waitId != "" {
		c.place.Done(waitId, &loginInfo{
			Error: bakeryErr.(*httpbakery.Error),
		})
	}
	identity.WriteError(c.params.Response, err)
}

// Bakery implements idp.Context.Bakery.
func (c *idpHandler) Bakery() *bakery.Service {
	return c.store.Service
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
	return userFromIdentity(&identity)
}

// FindUserByName implements idp.Context.FindUserByName.
func (c *idpHandler) FindUserByName(name params.Username) (*params.User, error) {
	id, err := c.store.GetIdentity(name)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return userFromIdentity(id)
}

// UpdateUser implements idp.Context.UpdateUser.
func (c *idpHandler) UpdateUser(u *params.User) error {
	id := identityFromUser(u)
	groups, err := c.store.GetLaunchpadGroups(id.ExternalID, id.Email)
	if err != nil {
		logger.Warningf("failed to fetch list of groups from launchpad for %q: %s", id.Email, err)
	}
	groups = append(id.Groups, groups...)
	err = c.store.SetGroups(id.Username, groups)
	if err != nil {
		if errgo.Cause(err) == params.ErrNotFound {
			err := c.store.InsertIdentity(id)
			if err != nil {
				return errgo.NoteMask(err, "cannot store identity", errgo.Is(params.ErrAlreadyExists))
			}
			return nil
		}
		return errgo.Mask(err)
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
