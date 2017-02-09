// Copyright 2014 Canonical Ltd.

package v1

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

var blacklistUsernames = map[params.Username]bool{
	"admin":             true,
	"everyone":          true,
	store.AdminUsername: true,
}

// QueryUsers serves the /u endpoint. See http://tinyurl.com/lu3mmr9 for
// details.
func (h *apiHandler) QueryUsers(p httprequest.Params, r *params.QueryUsersRequest) ([]string, error) {
	query := make(bson.D, 0, 4)
	if r.ExternalID != "" {
		query = append(query, bson.DocElem{"external_id", r.ExternalID})
	}
	if r.Email != "" {
		query = append(query, bson.DocElem{"email", r.Email})
	}
	if len(r.LastLoginSince) > 0 {
		var t time.Time
		if err := t.UnmarshalText([]byte(r.LastLoginSince)); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal last-login-since")
		}
		query = append(query, bson.DocElem{"lastlogin", bson.D{{"$gte", t}}})
	}
	if len(r.LastDischargeSince) > 0 {
		var t time.Time
		if err := t.UnmarshalText([]byte(r.LastDischargeSince)); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal last-discharge-since")
		}
		query = append(query, bson.DocElem{"lastdischarge", bson.D{{"$gte", t}}})
	}

	// TODO(mhilton) make sure this endpoint can be queried as a
	// subset once there are more users.

	var identities []mongodoc.Identity
	if err := h.store.DB.Identities().Find(query).All(&identities); err != nil {
		return nil, errgo.Mask(err)
	}
	usernames := make([]string, len(identities))
	for i, id := range identities {
		usernames[i] = id.Username
	}
	return usernames, nil
}

// User serves the /u/$username endpoint. See http://tinyurl.com/lrdjwmw
// for details.
func (h *apiHandler) User(p httprequest.Params, r *params.UserRequest) (*params.User, error) {
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return userFromIdentity(p.Context, id)
}

// SetUser creates or updates the user with the given username. If the
// user already exists then any IDPGroups or SSHKeys specified in the
// request will be ignored. See SetUserGroups, ModifyUserGroups,
// SetSSHKeys and DeleteSSHKeys if you wish to manipulate these for a
// user.
func (h *apiHandler) SetUser(p httprequest.Params, u *params.SetUserRequest) error {
	if u.Owner != "" {
		return h.setAgent(p, u)
	}
	if blacklistUsernames[u.Username] {
		return errgo.WithCausef(nil, params.ErrForbidden, "username %q is reserved", u.Username)
	}
	if u.ExternalID == "" {
		return errgo.WithCausef(nil, params.ErrBadRequest, `external_id not specified`)
	}
	doc := identityFromSetUserParams(u)
	if err := h.store.UpsertUser(doc); err != nil {
		if errgo.Cause(err) == store.ErrInvalidData {
			return errgo.WithCausef(err, params.ErrBadRequest, "")
		}
		return errgo.Mask(err, errgo.Is(params.ErrAlreadyExists))
	}
	return nil
}

// setAgent implements SetUser for agent users. An agent user is a user
// with an Owner and no ExternalID. An agent user can only have a subset
// of the groups to which the owner has access. Note: Currently only
// admin users can create agents.
func (h *apiHandler) setAgent(p httprequest.Params, u *params.SetUserRequest) error {
	if !strings.HasSuffix(string(u.Username), "@"+string(u.User.Owner)) {
		return errgo.WithCausef(nil, params.ErrForbidden, `%s cannot create user %q (suffix must be "@%s")`, u.User.Owner, u.Username, u.User.Owner)
	}
	// TODO we will need a mechanism to revoke groups from all agents
	// belonging to an owner if the owner loses the group.
	if err := checkMemberOfAllGroups(p.Context, u.User.IDPGroups); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrForbidden))
	}
	doc := identityFromSetUserParams(u)
	if err := h.store.UpsertAgent(doc); err != nil {
		if errgo.Cause(err) == store.ErrInvalidData {
			return errgo.WithCausef(err, params.ErrBadRequest, "")
		}
		return errgo.Mask(err, errgo.Is(params.ErrAlreadyExists))
	}
	return nil
}

func checkMemberOfAllGroups(ctx context.Context, groups []string) error {
	id := identityFromContext(ctx)
	if id == "" {
		return errgo.Newf("no authenticated identity found")
	}
	// TODO If Identity.Allow was more efficient, we could just call
	// id.Allow for each member of u.User.IDPGroups.
	idGroups, err := id.Groups(ctx)
	if err != nil {
		return errgo.Notef(err, "cannot get groups")
	}
	// Admins are considered to be a member of all groups.
	for _, g := range store.AdminACL {
		if string(id) == g {
			return nil
		}
	}

Outer:
	for _, g := range groups {
		for _, idg := range idGroups {
			if idg == g {
				continue Outer
			}
		}
		return errgo.WithCausef(err, params.ErrForbidden, "not a member of %q", g)
	}
	return nil
}

func identityFromSetUserParams(u *params.SetUserRequest) *mongodoc.Identity {
	id := identityFromUser(&u.User)
	id.Username = string(u.Username)
	return id
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

// WhoAmI returns authentication information on the client that is
// making the call.
func (h *apiHandler) WhoAmI(p httprequest.Params, arg *params.WhoAmIRequest) (params.WhoAmIResponse, error) {
	id := identityFromContext(p.Context)
	if id == "" {
		// Should never happen, as the endpoint should require authentication.
		return params.WhoAmIResponse{}, errgo.Newf("no identity")
	}
	return params.WhoAmIResponse{
		User: string(id),
	}, nil
}

// UserGroups serves the GET /u/$username/groups endpoint, and returns
// the list of groups associated with the user.
func (h *apiHandler) UserGroups(p httprequest.Params, r *params.UserGroupsRequest) ([]string, error) {
	groups, err := store.Identity(r.Username).Groups(p.Context)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	if groups == nil {
		groups = []string{}
	}
	return groups, nil
}

// UserIDPGroups serves the /u/$username/idpgroups endpoint, and returns
// the list of groups associated with the user. This endpoint should no longer be used
// and is maintained for backwards compatibility purposes only.
func (h *apiHandler) UserIDPGroups(p httprequest.Params, r *params.UserIDPGroupsRequest) ([]string, error) {
	return h.UserGroups(p, &params.UserGroupsRequest{
		Username: r.Username,
	})
}

// SetUserGroups serves the PUT /u/$username/groups endpoint, and sets the
// list of groups associated with the user.
func (h *apiHandler) SetUserGroups(p httprequest.Params, r *params.SetUserGroupsRequest) error {
	if err := h.store.SetGroups(r.Username, r.Groups.Groups); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

// ModifyUserGroups serves the POST /u/$username/groups endpoint, and
// updates the list of groups associated with the user. Groups can be
// either added or removed in a single query. It is an error to try and
// both add and remove groups at the same time.
func (h *apiHandler) ModifyUserGroups(p httprequest.Params, r *params.ModifyUserGroupsRequest) error {
	if len(r.Groups.Add) > 0 && len(r.Groups.Remove) > 0 {
		return errgo.WithCausef(nil, params.ErrBadRequest, "cannot add and remove groups in the same operation")
	}
	if len(r.Groups.Add) > 0 {
		return errgo.Mask(h.store.AddGroups(r.Username, r.Groups.Add), errgo.Is(params.ErrNotFound))
	} else {
		return errgo.Mask(h.store.RemoveGroups(r.Username, r.Groups.Remove), errgo.Is(params.ErrNotFound))
	}
}

// GetSSHKeys serves the /u/$username/sshkeys endpoint, and returns
// the list of ssh keys associated with the user.
func (h *apiHandler) GetSSHKeys(p httprequest.Params, r *params.SSHKeysRequest) (params.SSHKeysResponse, error) {
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return params.SSHKeysResponse{}, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return params.SSHKeysResponse{
		SSHKeys: id.SSHKeys,
	}, nil
}

// SetSSHKeys serves the /u/$username/sshkeys put endpoint, and set ssh keys to
// the list of ssh keys associated with the user. If the add parameter is set to
// true then it will only add to the current list of ssh keys
func (h *apiHandler) PutSSHKeys(p httprequest.Params, r *params.PutSSHKeysRequest) error {
	if r.Body.Add {
		err := h.store.UpdateIdentity(r.Username, bson.D{{"$addToSet", bson.D{{"ssh_keys", bson.D{{"$each", r.Body.SSHKeys}}}}}})
		if err != nil {
			return errgo.Mask(err, errgo.Is(params.ErrNotFound))
		}
		return nil
	}
	err := h.store.UpdateIdentity(r.Username, bson.D{{"$set", bson.D{{"ssh_keys", r.Body.SSHKeys}}}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

// DeleteSSHKeys serves the /u/$username/sshkeys delete endpoint, and remove
// ssh keys from the list of ssh keys associated with the user.
func (h *apiHandler) DeleteSSHKeys(p httprequest.Params, r *params.DeleteSSHKeysRequest) error {
	err := h.store.UpdateIdentity(r.Username, bson.D{{"$pull", bson.D{{"ssh_keys", bson.D{{"$in", r.Body.SSHKeys}}}}}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

// UserToken serves a token, in the form of a macaroon, identifying
// the user. This token can only be generated by an administrator.
func (h *apiHandler) UserToken(p httprequest.Params, r *params.UserTokenRequest) (*bakery.Macaroon, error) {
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	m, err := h.store.Bakery.Oven.NewMacaroon(
		p.Context,
		httpbakery.RequestVersion(p.Request),
		time.Now().Add(24*time.Hour),
		[]checkers.Caveat{
			idmclient.UserDeclaration(id.Username),
		},
		bakery.LoginOp,
	)
	if err != nil {
		return nil, errgo.Notef(err, "cannot mint macaroon")
	}
	return m, nil
}

func (h *apiHandler) VerifyToken(p httprequest.Params, r *params.VerifyTokenRequest) (map[string]string, error) {
	ctx := httpbakery.ContextWithRequest(p.Context, p.Request)
	authInfo, err := h.store.Bakery.Checker.Auth(r.Macaroons).Allow(ctx, bakery.LoginOp)
	if err != nil {
		// TODO only return ErrForbidden when the error is because of bad macaroons.
		return nil, errgo.WithCausef(err, params.ErrForbidden, `verification failure`)
	}
	return map[string]string{
		"username": authInfo.Identity.Id(),
	}, nil
}

// UserExtraInfo serves the /v1/u/:username/extra-info endpoint, see
// http://tinyurl.com/mxo24yy for details.
func (h *apiHandler) UserExtraInfo(p httprequest.Params, r *params.UserExtraInfoRequest) (map[string]interface{}, error) {
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

func userFromIdentity(ctx context.Context, id *mongodoc.Identity) (*params.User, error) {
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
	groups, err := store.Identity(id.Username).Groups(ctx)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if groups == nil {
		// Ensure that a null list of groups is never sent.
		groups = []string{}
	}
	return &params.User{
		Username:      params.Username(id.Username),
		ExternalID:    id.ExternalID,
		FullName:      id.FullName,
		Email:         id.Email,
		GravatarID:    id.GravatarID,
		IDPGroups:     groups,
		Owner:         params.Username(id.Owner),
		PublicKeys:    publicKeys,
		SSHKeys:       id.SSHKeys,
		LastLogin:     id.LastLogin,
		LastDischarge: id.LastDischarge,
	}, nil
}

func identityFromUser(u *params.User) *mongodoc.Identity {
	keys := make([]mongodoc.PublicKey, len(u.PublicKeys))
	for i, pk := range u.PublicKeys {
		keys[i].Key = pk.Key[:]
	}
	return &mongodoc.Identity{
		Username:      string(u.Username),
		ExternalID:    u.ExternalID,
		Email:         u.Email,
		GravatarID:    gravatarHash(u.Email),
		FullName:      u.FullName,
		Groups:        u.IDPGroups,
		Owner:         string(u.Owner),
		PublicKeys:    keys,
		LastLogin:     u.LastLogin,
		LastDischarge: u.LastDischarge,
	}
}
