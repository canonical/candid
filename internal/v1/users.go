// Copyright 2014 Canonical Ltd.

package v1

import (
	"encoding/json"
	"net/http"
	"strings"

	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/params"
)

// serveCreateUser serves the /u endpoint. See http://tinyurl.com/k5heg4q for
// details.
func (h *Handler) serveCreateUser(hdr http.Header, req *http.Request) (interface{}, error) {
	var user params.User
	dec := json.NewDecoder(req.Body)
	err := dec.Decode(&user)
	if err != nil {
		return nil, errgo.WithCausef(err, params.ErrBadRequest, `invalid JSON data`)
	}
	if user.UserName == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "no userid")
	}
	if user.IdentityProvider == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "no identity provider")
	}
	_, err = h.store.IdentityProvider(user.IdentityProvider)
	if err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return nil, errgo.WithCausef(nil, params.ErrBadRequest, `unsupported identity provider %q`, user.IdentityProvider)
		}
	}
	if err := h.store.AddIdentity(user.UserName, user.IdentityProvider); err != nil {
		if errgo.Cause(err) == params.ErrAlreadyExists {
			return nil, errgo.WithCausef(err, params.ErrBadRequest, "")
		}
		return nil, errgo.Notef(err, "cannot add identity")
	}
	return user, nil
}

//serveUser serves the /u/$username endpoint. See http://tinyurl.com/luaqrh3 for
// details.
func (h *Handler) serveUser(hdr http.Header, req *http.Request) (interface{}, error) {
	if req.Method != "GET" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "unsupported method %q", req.Method)
	}
	u := strings.TrimPrefix(req.URL.Path, "/")
	var user params.User
	if err := h.store.DB.Identities().Find(bson.M{"username": u}).One(&user); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return nil, errgo.WithCausef(err, params.ErrNotFound, "user %q not found", u)
		}
	}
	return user, nil
}
