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

type queryUsersRequest struct {
	httprequest.Route `httprequest:"GET /u" bson:",omitempty"`
	ExternalID        string `httprequest:"external_id,form" bson:"external_id,omitempty"`
}

// ServeQueryUsers serves the /u endpoint. See http://tinyurl.com/lu3mmr9 for
// details.
func (h *handler) ServeQueryUsers(p httprequest.Params, r *queryUsersRequest) ([]string, error) {
	if err := h.checkAdmin(p.Request); err != nil {
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

type usernameParam struct {
	Username params.Username `httprequest:"username,path"`
}

type userRequest struct {
	httprequest.Route `httprequest:"GET /u/:username"`
	usernameParam
}

//serveUser serves the /u/$username endpoint. See http://tinyurl.com/lrdjwmw for
// details.
func (h *handler) ServeUser(p httprequest.Params, r *userRequest) (*params.User, error) {
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

type putUserRequest struct {
	httprequest.Route `httprequest:"PUT /u/:username"`
	usernameParam
	User params.User `httprequest:",body"`
}

func (h *handler) ServePutUser(p httprequest.Params, u *putUserRequest) error {
	if u.User.Owner == "" {
		// If there is no owner specified then it is an interactive user being created
		// by storefront.
		return h.upsertUser(p.Request, u)
	}
	return h.upsertAgent(p.Request, u)
}

func (h *handler) upsertAgent(r *http.Request, u *putUserRequest) error {
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
	doc := identityFromPutUserParams(u)
	if err := h.store.UpsertIdentity(doc); err != nil {
		return errgo.NoteMask(err, "cannot store identity", errgo.Is(params.ErrAlreadyExists))
	}
	return nil
}

func (h *handler) upsertUser(r *http.Request, u *putUserRequest) error {
	if err := h.store.CheckACL(opCreateUser, r, []string{identity.AdminGroup}); err != nil {
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

func identityFromPutUserParams(u *putUserRequest) *mongodoc.Identity {
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

type userGroupsRequest struct {
	httprequest.Route `httprequest:"GET /u/:username/groups"`
	usernameParam
}

// serveUserGroups serves the /u/$username/groups endpoint, and returns
// the list of groups associated with the user.
func (h *handler) ServeUserGroups(p httprequest.Params, r *userGroupsRequest) ([]string, error) {
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

type userIDPGroupsRequest struct {
	httprequest.Route `httprequest:"GET /u/:username/idpgroups"`
	usernameParam
}

// ServeUserGroups serves the /u/$username/idpgroups endpoint, and returns
// the list of groups associated with the user. This endpoint should no longer be used
// and is maintained for backwards compatibility purposes only.
func (h *handler) ServeUserIDPGroups(p httprequest.Params, r *userIDPGroupsRequest) ([]string, error) {
	if err := h.checkAdmin(p.Request); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return id.Groups, nil
}

type userTokenRequest struct {
	httprequest.Route `httprequest:"GET /u/:username/macaroon"`
	usernameParam
}

// ServerUserToken serves a token, in the form of a macaroon, identifying
// the user. This token can only be generated by an afministrator.
func (h *handler) ServeUserToken(p httprequest.Params, r *userTokenRequest) (*macaroon.Macaroon, error) {
	if err := h.checkAdmin(p.Request); err != nil {
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

type verifyTokenRequest struct {
	httprequest.Route `httprequest:"POST /verify"`
	Macaroons         macaroon.Slice `httprequest:",body"`
}

func (h *handler) ServeVerifyToken(r *verifyTokenRequest) (map[string]string, error) {
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

type userExtraInfoRequest struct {
	httprequest.Route `httprequest:"GET /u/:username/extra-info"`
	usernameParam
}

//ServeUserExtraInfo serves the /u/:username/extra-info endpoint, see
//http://tinyurl.com/mxo24yy for details.
func (h *handler) ServeUserExtraInfo(p httprequest.Params, r *userExtraInfoRequest) (map[string]*json.RawMessage, error) {
	if err := h.checkAdmin(p.Request); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	id, err := h.store.GetIdentity(r.Username)
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

type userPutExtraInfoRequest struct {
	httprequest.Route `httprequest:"PUT /u/:username/extra-info"`
	usernameParam
	ExtraInfo map[string]json.RawMessage `httprequest:",body"`
}

// ServeUserPutExtraInfo serves the /u/:username/extra-info endpoint, see
// http://tinyurl.com/mqpynlw for details.
func (h *handler) ServeUserPutExtraInfo(p httprequest.Params, r *userPutExtraInfoRequest) error {
	if err := h.checkAdmin(p.Request); err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	ei := make(bson.D, 0, len(r.ExtraInfo))
	for k, v := range r.ExtraInfo {
		if err := checkExtraInfoKey(k); err != nil {
			return errgo.Mask(err, errgo.Is(params.ErrBadRequest))
		}
		ei = append(ei, bson.DocElem{"extrainfo." + k, v})
	}
	err := h.store.UpdateIdentity(r.Username, bson.D{{"$set", ei}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

type userExtraInfoItemRequest struct {
	httprequest.Route `httprequest:"GET /u/:username/extra-info/:item"`
	usernameParam
	Item string `httprequest:"item,path"`
}

// ServeUserExtraInfoItem serves the /u/:username/extra-info/:item
// endpoint, see http://tinyurl.com/mjuu7dt for details.
func (h *handler) ServeUserExtraInfoItem(p httprequest.Params, r *userExtraInfoItemRequest) (*json.RawMessage, error) {
	if err := h.checkAdmin(p.Request); err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	id, err := h.store.GetIdentity(r.Username)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	var res json.RawMessage = id.ExtraInfo[r.Item]
	return &res, nil
}

type userPutExtraInfoItemRequest struct {
	httprequest.Route `httprequest:"PUT /u/:username/extra-info/:item"`
	usernameParam
	Item string          `httprequest:"item,path"`
	Data json.RawMessage `httprequest:",body"`
}

// ServeUserPutExtraInfoItem serves the /u/:username/extra-info/:item
// endpoint, see http://tinyurl.com/l5dc4r4 for details.
func (h *handler) ServeUserPutExtraInfoItem(p httprequest.Params, r *userPutExtraInfoItemRequest) error {
	if err := h.checkAdmin(p.Request); err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	if err := checkExtraInfoKey(r.Item); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrBadRequest))
	}
	err := h.store.UpdateIdentity(r.Username, bson.D{{"$set", bson.D{
		{"extrainfo." + r.Item, r.Data},
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
