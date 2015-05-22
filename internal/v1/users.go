// Copyright 2014 Canonical Ltd.

package v1

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon.v1"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/server"
	"github.com/CanonicalLtd/blues-identity/params"
)

var blacklistUsernames = map[params.Username]bool{
	"admin":           true,
	"everyone":        true,
	server.AdminGroup: true,
}

type queryUsersParams struct {
	ExternalID string `httprequest:"external_id,form" bson:"external_id,omitempty"`
}

// serverQueryUsers serves the /u endpoint. See http://tinyurl.com/lu3mmr9 for
// details.
func (h *Handler) serveQueryUsers(_ http.Header, _ httprequest.Params, q *queryUsersParams) ([]string, error) {
	db := h.store.DB.Copy()
	defer db.Close()
	usernames := make([]string, 0, 1)
	var user mongodoc.Identity
	it := db.Identities().Find(q).Iter()
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
	var publicKeys []*bakery.PublicKey
	if len(id.PublicKeys) > 0 {
		publicKeys = make([]*bakery.PublicKey, len(id.PublicKeys))
		for i, key := range id.PublicKeys {
			var pk bakery.PublicKey
			if err := pk.UnmarshalBinary(key.Key); err != nil {
				return nil, errgo.Notef(err, "cannot unmarshal public key from database")
			}
			publicKeys[i] = &pk
		}
	}
	return &params.User{
		Username:   params.Username(id.Username),
		ExternalID: id.ExternalID,
		FullName:   id.FullName,
		Email:      id.Email,
		GravatarID: id.GravatarID,
		IDPGroups:  id.Groups,
		Owner:      params.Username(id.Owner),
		PublicKeys: publicKeys,
	}, nil
}

type putUserParams struct {
	usernameParam
	User params.User `httprequest:",body"`
}

func (h *Handler) servePutUser(_ http.ResponseWriter, p httprequest.Params, u *putUserParams) error {
	if u.User.Owner == "" {
		// If there is no owner specified then it is an interactive user being created
		// by storefront.
		return h.upsertUser(p.Request, u)
	}
	return h.upsertAgent(p.Request, u)
}

func (h *Handler) upsertAgent(r *http.Request, u *putUserParams) error {
	if u.User.Owner == "" {
		return errgo.WithCausef(nil, params.ErrBadRequest, "owner not specified")
	}
	err := h.auth.CheckACL(opCreateAgent, r, []string{
		server.AdminGroup,
		"+create-agent@" + string(u.User.Owner),
	})
	if err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	if !strings.HasSuffix(string(u.Username), "@"+string(u.User.Owner)) {
		return errgo.WithCausef(nil, params.ErrForbidden, `%s cannot create user %q (suffix must be "@%s")`, u.User.Owner, u.Username, u.User.Owner)
	}
	// TODO we will need a mechanism to revoke groups from all agents
	// belonging to an owner if the owner loses the group.
	if err := h.checkRequestHasAllGroups(r, u.User.IDPGroups); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrForbidden))
	}
	doc := identityFromPutUserParams(u)
	if err := h.store.UpsertIdentity(doc); err != nil {
		return errgo.NoteMask(err, "cannot store identity", errgo.Is(params.ErrAlreadyExists))
	}
	return nil
}

func (h *Handler) upsertUser(r *http.Request, u *putUserParams) error {
	if err := h.auth.CheckACL(opCreateUser, r, []string{server.AdminGroup}); err != nil {
		return errgo.Mask(err, errgo.Any)
	}

	if blacklistUsernames[u.Username] {
		return errgo.WithCausef(nil, params.ErrForbidden, "username %q is reserved", u.Username)
	}
	doc := identityFromPutUserParams(u)
	if doc.ExternalID == "" {
		return errgo.WithCausef(nil, params.ErrBadRequest, `external_id not specified`)
	}
	if err := h.store.UpsertIdentity(doc); err != nil {
		return errgo.NoteMask(err, "cannot store identity", errgo.Is(params.ErrAlreadyExists))
	}
	return nil
}

func identityFromPutUserParams(u *putUserParams) *mongodoc.Identity {
	keys := make([]mongodoc.PublicKey, len(u.User.PublicKeys))
	for i, pk := range u.User.PublicKeys {
		keys[i].Key = pk.Key[:]
	}
	return &mongodoc.Identity{
		Username:   string(u.Username),
		ExternalID: u.User.ExternalID,
		Email:      u.User.Email,
		GravatarID: gravatarHash(u.User.Email),
		FullName:   u.User.FullName,
		Groups:     u.User.IDPGroups,
		Owner:      string(u.User.Owner),
		PublicKeys: keys,
	}
}

func (h *Handler) checkRequestHasAllGroups(r *http.Request, groups []string) error {
	requestGroups, err := h.auth.GroupsFromRequest(opCreateAgent, r)
	if err != nil {
		return errgo.Notef(err, "cannot check groups")
	}
Outer:
	for _, group := range groups {
		for _, g := range requestGroups {
			if g == group || g == server.AdminGroup {
				continue Outer
			}
		}
		return errgo.WithCausef(err, params.ErrForbidden, "not a member of %q", group)
	}
	return nil
}

// Calculate the gravatar hash based on the following specification :
// https://en.gravatar.com/site/implement/hash
func gravatarHash(s string) string {
	if s == "" {
		return ""
	}
	hasher := md5.New()
	hasher.Write([]byte(strings.ToLower(strings.TrimSpace(s))))
	return fmt.Sprintf("%x", hasher.Sum(nil))
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

//serverUserExtraInfo serves the /u/:username/extra-info endpoint, see
//http://tinyurl.com/mxo24yy for details.
func (h *Handler) serveUserExtraInfo(_ http.Header, _ httprequest.Params, p *usernameParam) (map[string]*json.RawMessage, error) {
	id, err := h.store.GetIdentity(p.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	res := make(map[string]*json.RawMessage, len(id.ExtraInfo))
	for k, v := range id.ExtraInfo {
		jmsg := json.RawMessage(v)
		res[k] = &jmsg
	}
	return res, nil
}

type putExtraInfoParams struct {
	usernameParam
	ExtraInfo map[string]json.RawMessage `httprequest:",body"`
}

// serverUserPutExtraInfo serves the /u/:username/extra-info endpoint, see
// http://tinyurl.com/mqpynlw for details.
func (h *Handler) serveUserPutExtraInfo(_ http.ResponseWriter, _ httprequest.Params, p *putExtraInfoParams) error {
	ei := make(bson.D, 0, len(p.ExtraInfo))
	for k, v := range p.ExtraInfo {
		if err := checkExtraInfoKey(k); err != nil {
			return errgo.Mask(err, errgo.Is(params.ErrBadRequest))
		}
		ei = append(ei, bson.DocElem{"extrainfo." + k, v})
	}
	err := h.store.UpdateIdentity(p.Username, bson.D{{"$set", ei}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

type extraInfoItemParams struct {
	usernameParam
	Item string `httprequest:"item,path"`
}

// serverUserExtraInfoItem serves the /u/:username/extra-info/:item
// endpoint, see http://tinyurl.com/mjuu7dt for details.
func (h *Handler) serveUserExtraInfoItem(_ http.Header, _ httprequest.Params, p *extraInfoItemParams) (*json.RawMessage, error) {
	id, err := h.store.GetIdentity(p.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	var res json.RawMessage = id.ExtraInfo[p.Item]
	return &res, nil
}

type putExtraInfoItemParams struct {
	extraInfoItemParams
	Data json.RawMessage `httprequest:",body"`
}

// serverUserPutExtraInfoItem serves the /u/:username/extra-info/:item
// endpoint, see http://tinyurl.com/l5dc4r4 for details.
func (h *Handler) serveUserPutExtraInfoItem(_ http.ResponseWriter, _ httprequest.Params, p *putExtraInfoItemParams) error {
	if err := checkExtraInfoKey(p.Item); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrBadRequest))
	}
	err := h.store.UpdateIdentity(p.Username, bson.D{{"$set", bson.D{
		{"extrainfo." + p.Item, p.Data},
	}}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

func checkExtraInfoKey(key string) error {
	if strings.ContainsAny(key, "./$") {
		return errgo.WithCausef(nil, params.ErrBadRequest, "%q bad key for extra-info", key)
	}
	return nil
}
