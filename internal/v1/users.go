// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"
	"time"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v0/bakery/checkers"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

var blacklistUsernames = map[params.Username]bool{
	"admin":    true,
	"everyone": true,
}

type queryUsersParams struct {
	ExternalID string `httprequest:"external_id,form" bson:"external_id,omitempty"`
}

// serverQueryUsers serves the /u endpoint. See http://tinyurl.com/lu3mmr9 for
// details.
func (h *Handler) serveQueryUsers(_ http.Header, _ httprequest.Params, q *queryUsersParams) ([]string, error) {
	usernames := make([]string, 0, 1)
	var user mongodoc.Identity
	it := h.store.DB.Identities().Find(q).Iter()
	for it.Next(&user) {
		usernames = append(usernames, user.Username)
	}
	if err := it.Close(); err != nil {
		return nil, errgo.Mask(err)
	}
	return usernames, nil
}

type usernameParam struct {
	Username params.Username `httprequest:"username,path"`
}

//serveUser serves the /u/$username endpoint. See http://tinyurl.com/lrdjwmw for
// details.
func (h *Handler) serveUser(hdr http.Header, _ httprequest.Params, p *usernameParam) (*params.User, error) {
	id, err := h.store.GetIdentity(p.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return &params.User{
		Username:   params.Username(id.Username),
		ExternalID: id.ExternalID,
		FullName:   id.FullName,
		Email:      id.Email,
		IDPGroups:  id.Groups,
	}, nil
}

type putUserParams struct {
	usernameParam
	User params.User `httprequest:",body"`
}

func (h *Handler) servePutUser(_ http.ResponseWriter, _ httprequest.Params, u *putUserParams) error {
	if blacklistUsernames[u.Username] {
		return errgo.WithCausef(nil, params.ErrForbidden, "username %q is reserved", u.Username)
	}
	doc := &mongodoc.Identity{
		Username:   string(u.Username),
		ExternalID: u.User.ExternalID,
		Email:      u.User.Email,
		FullName:   u.User.FullName,
		Groups:     u.User.IDPGroups,
	}
	if doc.ExternalID == "" {
		return errgo.WithCausef(nil, params.ErrBadRequest, `external_id not specified`)
	}
	if err := h.store.UpsertIdentity(doc); err != nil {
		return errgo.NoteMask(err, "cannot store identity", errgo.Is(params.ErrAlreadyExists))
	}
	return nil
}

// serveUserGroups serves the /u/$username/idpgroups endpoint, and returns
// the list of groups associated with the user.
func (h *Handler) serveUserGroups(_ http.Header, _ httprequest.Params, p *usernameParam) ([]string, error) {
	id, err := h.store.GetIdentity(p.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return id.Groups, nil
}

func (h *Handler) serveUserToken(_ http.Header, _ httprequest.Params, p *usernameParam) (*macaroon.Macaroon, error) {
	id, err := h.store.GetIdentity(p.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	m, err := h.svc.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("uuid", id.UUID),
		checkers.DeclaredCaveat("username", id.Username),
		checkers.TimeBeforeCaveat(time.Now().Add(24 * time.Hour)),
	})
	if err != nil {
		return nil, errgo.Notef(err, "cannot mint macaroon")
	}
	return m, nil
}

type verifyTokenParams struct {
	Macaroons macaroon.Slice `httprequest:",body"`
}

func (h *Handler) serveVerifyToken(_ http.Header, _ httprequest.Params, p *verifyTokenParams) (map[string]string, error) {
	d := checkers.InferDeclared(p.Macaroons)
	err := h.svc.Check(p.Macaroons, checkers.New(
		checkers.TimeBefore,
		d,
	))
	if err != nil {
		return nil, errgo.WithCausef(err, params.ErrForbidden, `verification failure`)
	}
	return d, nil
}
