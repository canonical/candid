// Copyright 2014 Canonical Ltd.

package v1

import (
	"encoding/json"
	"net/http"
	"strings"

	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

// serverQueryUsers serves the /u endpoint. See http://tinyurl.com/lu3mmr9 for
// details.
func (h *Handler) serveQueryUsers(hdr http.Header, req *http.Request) (interface{}, error) {
	req.ParseForm()
	eid := req.Form.Get("external_id")
	usernames := make([]string, 0, 1)
	var user mongodoc.Identity
	var query = bson.M{}
	if eid != "" {
		query["external_id"] = eid
	}
	it := h.store.DB.Identities().Find(query).Iter()
	for it.Next(&user) {
		usernames = append(usernames, user.UserName)
	}
	if err := it.Close(); err != nil {
		return nil, errgo.Mask(err)
	}
	return usernames, nil
}

//serveUser serves the /u/$username endpoint. See http://tinyurl.com/lrdjwmw for
// details.
func (h *Handler) serveUser(hdr http.Header, req *http.Request) (interface{}, error) {
	switch req.Method {
	case "GET":
		u := strings.TrimPrefix(req.URL.Path, "/")
		var user mongodoc.Identity
		if err := h.store.DB.Identities().Find(bson.M{"username": u}).One(&user); err != nil {
			if errgo.Cause(err) == mgo.ErrNotFound {
				return nil, errgo.WithCausef(err, params.ErrNotFound, "user %q not found", u)
			}
		}
		return &params.User{
			UserName:   user.UserName,
			ExternalID: user.ExternalID,
			FullName:   user.FullName,
			Email:      user.Email,
			Groups:     user.Groups,
		}, nil
	case "PUT":
		u := strings.TrimPrefix(req.URL.Path, "/")
		if u == "" {
			return nil, errgo.WithCausef(nil, params.ErrBadRequest, "cannot store blank user")
		}
		var user params.User
		dec := json.NewDecoder(req.Body)
		err := dec.Decode(&user)
		if err != nil {
			return nil, errgo.WithCausef(err, params.ErrBadRequest, `invalid JSON data`)
		}
		doc := &mongodoc.Identity{
			UserName:   u,
			ExternalID: user.ExternalID,
			Email:      user.Email,
			FullName:   user.FullName,
			Groups:     user.Groups,
		}
		err = h.store.UpsertIdentity(doc)
		if err != nil {
			return nil, errgo.NoteMask(err, "cannot store identity", errgo.Is(params.ErrAlreadyExists))
		}
		user.UserName = u
		return user, nil
	default:
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "unsupported method %q", req.Method)
	}
}
