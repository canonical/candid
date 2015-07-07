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

	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

var blacklistUsernames = map[params.Username]bool{
	"admin":             true,
	"everyone":          true,
	identity.AdminGroup: true,
}

// QueryUsers serves the /u endpoint. See http://tinyurl.com/lu3mmr9 for
// details.
func (h *apiHandler) QueryUsers(p httprequest.Params, r *params.QueryUsersRequest) ([]string, error) {
	if err := h.checkAdmin(); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	usernames := make([]string, 0, 1)
	var user mongodoc.Identity
	it := h.store.DB.Identities().Find(r).Iter()
	for it.Next(&user) {
		usernames = append(usernames, user.Username)
	}
	if err := it.Close(); err != nil {
		return nil, errgo.Mask(err)
	}
	return usernames, nil
}

// User serves the /u/$username endpoint. See http://tinyurl.com/lrdjwmw
// for details.
func (h *apiHandler) User(p httprequest.Params, r *params.UserRequest) (*params.User, error) {
	acl := []string{identity.AdminGroup, string(r.Username)}
	if err := h.store.CheckACL(opGetUser, p.Request, acl); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	id, err := h.store.GetIdentity(r.Username)
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

func (h *apiHandler) SetUser(p httprequest.Params, u *params.SetUserRequest) error {
	if u.User.Owner == "" {
		// If there is no owner specified then it is an interactive user being created
		// by storefront.
		return h.upsertUser(p.Request, u)
	}
	return h.upsertAgent(p.Request, u)
}

func (h *handler) upsertAgent(r *http.Request, u *params.SetUserRequest) error {
	if u.User.Owner == "" {
		return errgo.WithCausef(nil, params.ErrBadRequest, "owner not specified")
	}
	err := h.store.CheckACL(opCreateAgent, r, []string{
		identity.AdminGroup,
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
	doc := identityFromSetUserParams(u)
	if err := h.store.UpsertIdentity(doc); err != nil {
		return errgo.NoteMask(err, "cannot store identity", errgo.Is(params.ErrAlreadyExists))
	}
	return nil
}

func (h *apiHandler) upsertUser(r *http.Request, u *params.SetUserRequest) error {
	if err := h.store.CheckACL(opCreateUser, r, []string{identity.AdminGroup}); err != nil {
		return errgo.Mask(err, errgo.Any)
	}

	if blacklistUsernames[u.Username] {
		return errgo.WithCausef(nil, params.ErrForbidden, "username %q is reserved", u.Username)
	}
	doc := identityFromSetUserParams(u)
	if doc.ExternalID == "" {
		return errgo.WithCausef(nil, params.ErrBadRequest, `external_id not specified`)
	}
	if err := h.store.UpsertIdentity(doc); err != nil {
		return errgo.NoteMask(err, "cannot store identity", errgo.Is(params.ErrAlreadyExists))
	}
	return nil
}

func identityFromSetUserParams(u *params.SetUserRequest) *mongodoc.Identity {
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

func (h *handler) checkRequestHasAllGroups(r *http.Request, groups []string) error {
	requestGroups, err := h.store.GroupsFromRequest(opCreateAgent, r)
	if err != nil {
		return errgo.Notef(err, "cannot check groups")
	}
Outer:
	for _, group := range groups {
		for _, g := range requestGroups {
			if g == group || g == identity.AdminGroup {
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

// serveUserGroups serves the /u/$username/groups endpoint, and returns
// the list of groups associated with the user.
func (h *apiHandler) UserGroups(p httprequest.Params, r *params.UserGroupsRequest) ([]string, error) {
	// Administrators, users with GroupList permissions and the user
	// themselves can list their groups.
	if err := h.store.CheckACL(
		opGetUserGroups,
		p.Request,
		[]string{identity.AdminGroup, identity.GroupListGroup, string(r.Username)},
	); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return id.Groups, nil
}

// UserIDPGroups serves the /u/$username/idpgroups endpoint, and returns
// the list of groups associated with the user. This endpoint should no longer be used
// and is maintained for backwards compatibility purposes only.
func (h *apiHandler) UserIDPGroups(p httprequest.Params, r *params.UserIDPGroupsRequest) ([]string, error) {
	if err := h.checkAdmin(); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return id.Groups, nil
}

// UserToken serves a token, in the form of a macaroon, identifying
// the user. This token can only be generated by an administrator.
func (h *apiHandler) UserToken(p httprequest.Params, r *params.UserTokenRequest) (*macaroon.Macaroon, error) {
	if err := h.checkAdmin(); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	m, err := h.store.Service.NewMacaroon("", nil, []checkers.Caveat{
		checkers.DeclaredCaveat("uuid", id.UUID),
		checkers.DeclaredCaveat("username", id.Username),
		checkers.TimeBeforeCaveat(time.Now().Add(24 * time.Hour)),
	})
	if err != nil {
		return nil, errgo.Notef(err, "cannot mint macaroon")
	}
	return m, nil
}

func (h *apiHandler) VerifyToken(r *params.VerifyTokenRequest) (map[string]string, error) {
	d := checkers.InferDeclared(r.Macaroons)
	err := h.store.Service.Check(r.Macaroons, checkers.New(
		checkers.TimeBefore,
		d,
	))
	if err != nil {
		return nil, errgo.WithCausef(err, params.ErrForbidden, `verification failure`)
	}
	return d, nil
}

// UserExtraInfo serves the /v1/u/:username/extra-info endpoint, see
// http://tinyurl.com/mxo24yy for details.
func (h *apiHandler) UserExtraInfo(p httprequest.Params, r *params.UserExtraInfoRequest) (map[string]interface{}, error) {
	if err := h.checkAdmin(); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	res := make(map[string]interface{}, len(id.ExtraInfo))
	for k, v := range id.ExtraInfo {
		jmsg := json.RawMessage(v)
		res[k] = &jmsg
	}
	return res, nil
}

// SetUserExtraInfo serves the /v1/u/:username/extra-info endpoint, see
// http://tinyurl.com/mqpynlw for details.
func (h *apiHandler) SetUserExtraInfo(p httprequest.Params, r *params.SetUserExtraInfoRequest) error {
	if err := h.checkAdmin(); err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	ei := make(bson.D, 0, len(r.ExtraInfo))
	for k, v := range r.ExtraInfo {
		if err := checkExtraInfoKey(k); err != nil {
			return errgo.Mask(err, errgo.Is(params.ErrBadRequest))
		}
		buf, err := json.Marshal(v)
		if err != nil {
			// This should not be possible as it was only just unmarshalled.
			panic(err)
		}
		ei = append(ei, bson.DocElem{"extrainfo." + k, buf})
	}
	err := h.store.UpdateIdentity(r.Username, bson.D{{"$set", ei}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

// UserExtraInfoItem serves the /u/:username/extra-info/:item
// endpoint, see http://tinyurl.com/mjuu7dt for details.
func (h *apiHandler) UserExtraInfoItem(p httprequest.Params, r *params.UserExtraInfoItemRequest) (interface{}, error) {
	if err := h.checkAdmin(); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	var res json.RawMessage = id.ExtraInfo[r.Item]
	return &res, nil
}

// ServeUserPutExtraInfoItem serves the /u/:username/extra-info/:item
// endpoint, see http://tinyurl.com/l5dc4r4 for details.
func (h *apiHandler) SetUserExtraInfoItem(p httprequest.Params, r *params.SetUserExtraInfoItemRequest) error {
	if err := h.checkAdmin(); err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	if err := checkExtraInfoKey(r.Item); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrBadRequest))
	}
	buf, err := json.Marshal(r.Data)
	if err != nil {
		// This should not be possible as it was only just unmarshalled.
		panic(err)
	}
	err = h.store.UpdateIdentity(r.Username, bson.D{{"$set", bson.D{
		{"extrainfo." + r.Item, buf},
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
