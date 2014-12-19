// Copyright 2014 Canonical Ltd.

package v1

import (
	"encoding/json"
	"net/http"

	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"

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
