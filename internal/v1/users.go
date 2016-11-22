// Copyright 2014 Canonical Ltd.

package v1

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

var blacklistUsernames = map[params.Username]bool{
	"admin":          true,
	"everyone":       true,
	store.AdminGroup: true,
}

var storeGetLaunchpadGroups = (*store.Store).GetLaunchpadGroups

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
	acl := []string{store.AdminGroup, string(r.Username)}
	if err := h.store.CheckACL(opGetUser, p.Request, acl); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return userFromIdentity(h.store, id)
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
	if err := h.store.CheckACL(opCreateUser, p.Request, []string{store.AdminGroup}); err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	if blacklistUsernames[u.Username] {
		return errgo.WithCausef(nil, params.ErrForbidden, "username %q is reserved", u.Username)
	}
	if u.ExternalID == "" {
		return errgo.WithCausef(nil, params.ErrBadRequest, `external_id not specified`)
	}

	// We would like to always set the user information to that
	// specified in u here, but this endpoint has historically been
	// used in such a way that this could cause information to be
	// lost. Groups and SSH keys will not be set unless a new user is
	// being created.
	doc := identityFromSetUserParams(u)
	onInsert := make(bson.D, 0, 3) // store.UpsertUser will append one item to this array, so we might as well only allocate once.
	if doc.Groups != nil {
		onInsert = append(onInsert, bson.DocElem{"groups", doc.Groups})
		doc.Groups = nil
	}
	if doc.SSHKeys != nil {
		onInsert = append(onInsert, bson.DocElem{"ssh_keys", doc.SSHKeys})
		doc.SSHKeys = nil
	}
	if err := h.store.UpsertIdentity(doc, onInsert); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrAlreadyExists))
	}
	return nil
}

// setAgent implements SetUser for agent users. An agent user is a user
// with an Owner and no ExternalID. An agent user can only have a subset
// of the groups to which the owner has access. Note: Currently only
// admin users can create agents.
func (h *apiHandler) setAgent(p httprequest.Params, u *params.SetUserRequest) error {
	err := h.store.CheckACL(opCreateAgent, p.Request, []string{
		store.AdminGroup,
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
	if err := h.checkRequestHasAllGroups(p.Request, u.User.IDPGroups); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrForbidden))
	}

	doc := identityFromSetUserParams(u)
	if err := h.store.UpsertIdentity(doc, nil); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrAlreadyExists))
	}
	return nil
}

func identityFromSetUserParams(u *params.SetUserRequest) *mongodoc.Identity {
	id := identityFromUser(&u.User)
	id.Username = string(u.Username)
	return id
}

func (h *handler) checkRequestHasAllGroups(r *http.Request, groups []string) error {
	requestGroups, err := h.store.GroupsFromRequest(opCreateAgent, r)
	if err != nil {
		return errgo.Notef(err, "cannot check groups")
	}
Outer:
	for _, group := range groups {
		for _, g := range requestGroups {
			if g == group || g == store.AdminGroup {
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

// UserGroups serves the GET /u/$username/groups endpoint, and returns
// the list of groups associated with the user.
func (h *apiHandler) UserGroups(p httprequest.Params, r *params.UserGroupsRequest) ([]string, error) {
	// Administrators, users with GroupList permissions and the user
	// themselves can list their groups.
	if err := h.store.CheckACL(
		opGetUserGroups,
		p.Request,
		[]string{store.AdminGroup, store.GroupListGroup, string(r.Username)},
	); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return userGroups(h.store, id), nil
}

func userGroups(store *store.Store, id *mongodoc.Identity) []string {
	lpGroups, err := storeGetLaunchpadGroups(store, id.ExternalID)
	if err != nil {
		logger.Errorf("Failed to get launchpad groups for user: %s", err)
	}
	return uniqueStrings(append(id.Groups, lpGroups...))
}

// SetUserGroups serves the PUT /u/$username/groups endpoint, and sets the
// list of groups associated with the user.
func (h *apiHandler) SetUserGroups(p httprequest.Params, r *params.SetUserGroupsRequest) error {
	// Only administrators can set a user's groups.
	if err := h.store.CheckACL(
		opSetUserGroups,
		p.Request,
		[]string{store.AdminGroup},
	); err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	if err := h.store.SetGroups(r.Username, r.Groups.Groups); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

// ModifyUserGroups serves the POST /u/$username/groups endpoint, and
// updates the list of groups associated with the user. Groups are added
// to the user before they are removed, so if there is a group name in
// both lists then it will ultimately be removed from the user.
func (h *apiHandler) ModifyUserGroups(p httprequest.Params, r *params.ModifyUserGroupsRequest) error {
	// Only administrators can update a user's groups.
	if err := h.store.CheckACL(
		opSetUserGroups,
		p.Request,
		[]string{store.AdminGroup},
	); err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	if err := h.store.AddGroups(r.Username, r.Groups.Add); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	if err := h.store.RemoveGroups(r.Username, r.Groups.Remove); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

// uniqueStrings removes all duplicates from the supplied
// string slice, updating the slice in place.
// The values will be in lexicographic order.
func uniqueStrings(ss []string) []string {
	if len(ss) < 2 {
		return ss
	}
	sort.Strings(ss)
	prev := ss[0]
	out := ss[:1]
	for _, s := range ss[1:] {
		if s == prev {
			continue
		}
		out = append(out, s)
		prev = s
	}
	return out
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
	return userGroups(h.store, id), nil
}

// GetSSHKeys serves the /u/$username/sshkeys endpoint, and returns
// the list of ssh keys associated with the user.
func (h *apiHandler) GetSSHKeys(p httprequest.Params, r *params.SSHKeysRequest) (params.SSHKeysResponse, error) {
	acl := []string{store.AdminGroup, store.SSHKeyGetterGroup, string(r.Username)}
	if err := h.store.CheckACL(opGetUserSSHKey, p.Request, acl); err != nil {
		return params.SSHKeysResponse{}, errgo.Mask(err, errgo.Any)
	}
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
	acl := []string{store.AdminGroup, string(r.Username)}
	if err := h.store.CheckACL(opSetUserSSHKey, p.Request, acl); err != nil {
		return errgo.Mask(err, errgo.Any)
	}
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
	acl := []string{store.AdminGroup, string(r.Username)}
	if err := h.store.CheckACL(opSetUserSSHKey, p.Request, acl); err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	err := h.store.UpdateIdentity(r.Username, bson.D{{"$pull", bson.D{{"ssh_keys", bson.D{{"$in", r.Body.SSHKeys}}}}}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
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
	m, err := h.store.Service.NewMacaroon(httpbakery.RequestVersion(p.Request),
		[]checkers.Caveat{
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

func userFromIdentity(store *store.Store, id *mongodoc.Identity) (*params.User, error) {
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
		IDPGroups:  userGroups(store, id),
		Owner:      params.Username(id.Owner),
		PublicKeys: publicKeys,
		SSHKeys:    id.SSHKeys,
	}, nil
}

func identityFromUser(u *params.User) *mongodoc.Identity {
	keys := make([]mongodoc.PublicKey, len(u.PublicKeys))
	for i, pk := range u.PublicKeys {
		keys[i].Key = pk.Key[:]
	}
	return &mongodoc.Identity{
		Username:   string(u.Username),
		ExternalID: u.ExternalID,
		Email:      u.Email,
		GravatarID: gravatarHash(u.Email),
		FullName:   u.FullName,
		Groups:     u.IDPGroups,
		Owner:      string(u.Owner),
		PublicKeys: keys,
	}
}
