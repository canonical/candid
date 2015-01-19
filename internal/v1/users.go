// Copyright 2014 Canonical Ltd.

package v1

import (
	"encoding/json"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/juju/names"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v0/bakery/checkers"
	"gopkg.in/macaroon.v1"
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
	if req.URL.Path != "/" {
		return nil, errgo.WithCausef(nil, params.ErrNotFound, "%s not found", req.URL.Path)
	}
	switch req.Method {
	case "PUT":
		un := req.Header.Get("X-Saved-Value-Username")
		if utf8.RuneCountInString(un) > 256 {
			return nil, errgo.WithCausef(nil, params.ErrBadRequest, "username longer than 256 characters")
		}
		if !names.IsValidUserName(un) {
			return nil, errgo.WithCausef(nil, params.ErrBadRequest, "illegal username: %q", un)
		}
		var user params.User
		dec := json.NewDecoder(req.Body)
		err := dec.Decode(&user)
		if err != nil {
			return nil, errgo.WithCausef(err, params.ErrBadRequest, `invalid JSON data`)
		}
		doc := &mongodoc.Identity{
			UserName:   un,
			ExternalID: user.ExternalID,
			Email:      user.Email,
			FullName:   user.FullName,
			Groups:     user.IDPGroups,
		}
		if doc.ExternalID == "" {
			return nil, errgo.WithCausef(err, params.ErrBadRequest, `external_id not specified`)
		}
		err = h.store.UpsertIdentity(doc)
		if err != nil {
			return nil, errgo.NoteMask(err, "cannot store identity", errgo.Is(params.ErrAlreadyExists))
		}
		fallthrough
	case "GET":
		user, err := h.lookupIdentity(req)
		if err != nil {
			return nil, err
		}
		return &params.User{
			UserName:   user.UserName,
			ExternalID: user.ExternalID,
			FullName:   user.FullName,
			Email:      user.Email,
			IDPGroups:  user.Groups,
		}, nil
	default:
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "unsupported method %q", req.Method)
	}
}

// serveUserGroups serves the /u/$username/idpgroups endpoint, and returns
// the list of groups associated with the user.
func (h *Handler) serveUserGroups(hdr http.Header, req *http.Request) (interface{}, error) {
	user, err := h.lookupIdentity(req)
	if err != nil {
		return nil, err
	}
	return user.Groups, nil
}

func (h *Handler) serveUserToken(hdr http.Header, req *http.Request) (interface{}, error) {
	user, err := h.lookupIdentity(req)
	if err != nil {
		return nil, err
	}
	m, err := h.svc.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("uuid", user.UUID),
		checkers.DeclaredCaveat("username", user.UserName),
		checkers.TimeBeforeCaveat(time.Now().Add(24 * time.Hour)),
	})
	if err != nil {
		return nil, errgo.Notef(err, "cannot mint macaroon")
	}
	return m, nil
}

func (h *Handler) serveVerifyToken(hdr http.Header, req *http.Request) (interface{}, error) {
	var ms macaroon.Slice
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&ms); err != nil {
		return nil, errgo.WithCausef(err, params.ErrBadRequest, `invalid JSON data`)
	}
	d := checkers.InferDeclared(ms)
	err := h.svc.Check(ms, checkers.New(
		checkers.TimeBefore,
		d,
	))
	if err != nil {
		return nil, errgo.WithCausef(err, params.ErrForbidden, `verification failure`)
	}
	return d, nil
}

func (h *Handler) lookupIdentity(r *http.Request) (*mongodoc.Identity, error) {
	var id mongodoc.Identity
	un := r.Header.Get("X-Saved-Value-Username")
	if err := h.store.DB.Identities().Find(bson.M{"username": un}).One(&id); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return nil, errgo.WithCausef(err, params.ErrNotFound, "user %q not found", un)
		}
	}
	return &id, nil
}
