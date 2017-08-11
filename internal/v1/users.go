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
	macaroon "gopkg.in/macaroon.v2-unstable"

	"github.com/CanonicalLtd/blues-identity/internal/auth"
	"github.com/CanonicalLtd/blues-identity/store"
)

var blacklistUsernames = map[params.Username]bool{
	"admin":            true,
	"everyone":         true,
	auth.AdminUsername: true,
}

// QueryUsers serves the /u endpoint. See http://tinyurl.com/lu3mmr9 for
// details.
func (h *apiHandler) QueryUsers(p httprequest.Params, r *params.QueryUsersRequest) ([]string, error) {
	var identity store.Identity
	var filter store.Filter
	if r.ExternalID != "" {
		identity.ProviderID = store.ProviderIdentity(r.ExternalID)
		filter[store.ProviderID] = store.Equal
	}
	if r.Email != "" {
		identity.Email = r.Email
		filter[store.Email] = store.Equal
	}
	if len(r.LastLoginSince) > 0 {
		var t time.Time
		if err := t.UnmarshalText([]byte(r.LastLoginSince)); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal last-login-since")
		}
		identity.LastLogin = t
		filter[store.LastLogin] = store.GreaterThanOrEqual
	}
	if len(r.LastDischargeSince) > 0 {
		var t time.Time
		if err := t.UnmarshalText([]byte(r.LastDischargeSince)); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal last-discharge-since")
		}
		identity.LastDischarge = t
		filter[store.LastDischarge] = store.GreaterThanOrEqual
	}

	// TODO(mhilton) make sure this endpoint can be queried as a
	// subset once there are more users.
	identities, err := h.h.store.FindIdentities(p.Context, &identity, filter, []store.Sort{{Field: store.Username}}, 0, 0)
	if err != nil {
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
	id := store.Identity{
		Username: string(r.Username),
	}
	err := h.h.store.Identity(p.Context, &id)
	if err != nil {
		return nil, translateStoreError(err)
	}
	return h.userFromIdentity(p.Context, &id)
}

// SetUser creates or updates the user with the given username. If the
// user already exists then any IDPGroups or SSHKeys specified in the
// request will be ignored. See SetUserGroups, ModifyUserGroups,
// SetSSHKeys and DeleteSSHKeys if you wish to manipulate these for a
// user.
func (h *apiHandler) SetUser(p httprequest.Params, u *params.SetUserRequest) error {
	if err := validateUsername(u); err != nil {
		return errgo.WithCausef(err, params.ErrForbidden, "")
	}
	identity := store.Identity{
		ProviderID: store.ProviderIdentity(u.User.ExternalID),
		Username:   string(u.Username),
		Name:       u.User.FullName,
		Email:      u.User.Email,
		Groups:     u.User.IDPGroups,
		PublicKeys: publicKeys(u.User.PublicKeys),
	}
	update := store.Update{
		store.Username:   store.Set,
		store.PublicKeys: store.Set,
		store.Groups:     store.Push,
	}
	if u.Owner != "" {
		if u.ExternalID != "" {
			return errgo.WithCausef(nil, params.ErrBadRequest, `both owner and external_id specified`)
		}
		identity.ProviderID = store.MakeProviderIdentity("idm", identity.Username)
		identity.ProviderInfo = map[string][]string{
			"owner": []string{string(u.Owner)},
		}
		update[store.ProviderInfo] = store.Push
		update[store.Groups] = store.Set
	}
	if identity.ProviderID == "" {
		return errgo.WithCausef(nil, params.ErrBadRequest, `external_id not specified`)
	}
	if identity.Name != "" {
		update[store.Name] = store.Set
	}
	if identity.Email != "" {
		update[store.Email] = store.Set
	}
	if len(u.User.SSHKeys) > 0 {
		update[store.ExtraInfo] = store.Push
		identity.ExtraInfo["sshkeys"] = u.User.SSHKeys
	}
	return translateStoreError(h.h.store.UpdateIdentity(p.Context, &identity, update))
}

func validateUsername(u *params.SetUserRequest) error {
	if blacklistUsernames[u.Username] {
		return errgo.Newf("username %q is reserved", u.Username)
	}
	if u.User.Owner != "" && !strings.HasSuffix(string(u.Username), "@"+string(u.User.Owner)) {
		return errgo.Newf(`%s cannot create user %q (suffix must be "@%s")`, u.User.Owner, u.Username, u.User.Owner)
	}
	return nil
}

func publicKeys(pks []*bakery.PublicKey) []bakery.PublicKey {
	pks2 := make([]bakery.PublicKey, len(pks))
	for i, pk := range pks {
		pks2[i] = *pk
	}
	return pks2
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
	if id == nil || id.Id() == "" {
		// Should never happen, as the endpoint should require authentication.
		return params.WhoAmIResponse{}, errgo.Newf("no identity")
	}
	return params.WhoAmIResponse{
		User: string(id.Id()),
	}, nil
}

// UserGroups serves the GET /u/$username/groups endpoint, and returns
// the list of groups associated with the user.
func (h *apiHandler) UserGroups(p httprequest.Params, r *params.UserGroupsRequest) ([]string, error) {
	id, err := h.h.auth.Identity(p.Context, string(r.Username))
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	groups, err := id.Groups(p.Context)
	if err != nil {
		return nil, errgo.Mask(err)
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
	identity := store.Identity{
		Username: string(r.Username),
		Groups:   r.Groups.Groups,
	}
	return translateStoreError(h.h.store.UpdateIdentity(p.Context, &identity, store.Update{store.Groups: store.Set}))
}

// ModifyUserGroups serves the POST /u/$username/groups endpoint, and
// updates the list of groups associated with the user. Groups can be
// either added or removed in a single query. It is an error to try and
// both add and remove groups at the same time.
func (h *apiHandler) ModifyUserGroups(p httprequest.Params, r *params.ModifyUserGroupsRequest) error {
	identity := store.Identity{
		Username: string(r.Username),
	}
	var update store.Update
	if len(r.Groups.Add) > 0 && len(r.Groups.Remove) > 0 {
		return errgo.WithCausef(nil, params.ErrBadRequest, "cannot add and remove groups in the same operation")
	}
	if len(r.Groups.Add) > 0 {
		identity.Groups = r.Groups.Add
		update[store.Groups] = store.Push
	} else {
		identity.Groups = r.Groups.Remove
		update[store.Groups] = store.Pull
	}
	return translateStoreError(h.h.store.UpdateIdentity(p.Context, &identity, update))
}

// GetSSHKeys serves the /u/$username/sshkeys endpoint, and returns
// the list of ssh keys associated with the user.
func (h *apiHandler) GetSSHKeys(p httprequest.Params, r *params.SSHKeysRequest) (params.SSHKeysResponse, error) {
	id := store.Identity{
		Username: string(r.Username),
	}
	if err := h.h.store.Identity(p.Context, &id); err != nil {
		return params.SSHKeysResponse{}, translateStoreError(err)
	}
	return params.SSHKeysResponse{
		SSHKeys: id.ExtraInfo["sshkeys"],
	}, nil
}

// PutSSHKeys serves the /u/$username/sshkeys put endpoint, and set ssh keys to
// the list of ssh keys associated with the user. If the add parameter is set to
// true then it will only add to the current list of ssh keys
func (h *apiHandler) PutSSHKeys(p httprequest.Params, r *params.PutSSHKeysRequest) error {
	id := store.Identity{
		Username: string(r.Username),
		ExtraInfo: map[string][]string{
			"sshkeys": r.Body.SSHKeys,
		},
	}
	update := store.Update{
		store.ExtraInfo: store.Push,
	}
	return translateStoreError(h.h.store.UpdateIdentity(p.Context, &id, update))
}

// DeleteSSHKeys serves the /u/$username/sshkeys delete endpoint, and remove
// ssh keys from the list of ssh keys associated with the user.
func (h *apiHandler) DeleteSSHKeys(p httprequest.Params, r *params.DeleteSSHKeysRequest) error {
	id := store.Identity{
		Username: string(r.Username),
		ExtraInfo: map[string][]string{
			"sshkeys": r.Body.SSHKeys,
		},
	}
	update := store.Update{
		store.ExtraInfo: store.Pull,
	}
	return translateStoreError(h.h.store.UpdateIdentity(p.Context, &id, update))
}

// UserToken serves a token, in the form of a macaroon, identifying
// the user. This token can only be generated by an administrator.
func (h *apiHandler) UserToken(p httprequest.Params, r *params.UserTokenRequest) (*bakery.Macaroon, error) {
	id, err := h.h.auth.Identity(p.Context, string(r.Username))
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	m, err := h.h.oven.NewMacaroon(
		p.Context,
		httpbakery.RequestVersion(p.Request),
		time.Now().Add(24*time.Hour),
		[]checkers.Caveat{
			idmclient.UserDeclaration(id.Id()),
		},
		bakery.LoginOp,
	)
	if err != nil {
		return nil, errgo.Notef(err, "cannot mint macaroon")
	}
	return m, nil
}

func (h *apiHandler) VerifyToken(p httprequest.Params, r *params.VerifyTokenRequest) (map[string]string, error) {
	authInfo, err := h.h.auth.Auth(p.Context, []macaroon.Slice{r.Macaroons}, bakery.LoginOp)
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
	id := store.Identity{
		Username: string(r.Username),
	}
	if err := h.h.store.Identity(p.Context, &id); err != nil {
		return nil, translateStoreError(err)
	}
	res := make(map[string]interface{}, len(id.ExtraInfo))
	for k, v := range id.ExtraInfo {
		if k == "sshkeys" {
			continue
		}
		jmsg := json.RawMessage(v[0])
		res[k] = &jmsg
	}
	return res, nil
}

// SetUserExtraInfo serves the /v1/u/:username/extra-info endpoint, see
// http://tinyurl.com/mqpynlw for details.
func (h *apiHandler) SetUserExtraInfo(p httprequest.Params, r *params.SetUserExtraInfoRequest) error {
	id := store.Identity{
		Username:  string(r.Username),
		ExtraInfo: make(map[string][]string, len(r.ExtraInfo)),
	}
	for k, v := range r.ExtraInfo {
		if err := checkExtraInfoKey(k); err != nil {
			return errgo.Mask(err, errgo.Is(params.ErrBadRequest))
		}
		buf, err := json.Marshal(v)
		if err != nil {
			// This should not be possible as it was only just unmarshalled.
			panic(err)
		}
		id.ExtraInfo[k] = []string{string(buf)}
	}
	return translateStoreError(h.h.store.UpdateIdentity(p.Context, &id, store.Update{store.ExtraInfo: store.Set}))
}

// UserExtraInfoItem serves the /u/:username/extra-info/:item
// endpoint, see http://tinyurl.com/mjuu7dt for details.
func (h *apiHandler) UserExtraInfoItem(p httprequest.Params, r *params.UserExtraInfoItemRequest) (interface{}, error) {
	id := store.Identity{
		Username: string(r.Username),
	}
	if err := h.h.store.Identity(p.Context, &id); err != nil {
		return nil, translateStoreError(err)
	}
	if len(id.ExtraInfo[r.Item]) != 1 {
		return nil, nil
	}
	var v interface{}
	if err := json.Unmarshal([]byte(id.ExtraInfo[r.Item][0]), &v); err != nil {
		// if it doesn't unmarshal its probably wasn't json in
		// the first place, so it probably doesn't matter.
		return nil, nil
	}
	return v, nil
}

// SetUserExtraInfoItem serves the /u/:username/extra-info/:item
// endpoint, see http://tinyurl.com/l5dc4r4 for details.
func (h *apiHandler) SetUserExtraInfoItem(p httprequest.Params, r *params.SetUserExtraInfoItemRequest) error {
	id := store.Identity{
		Username: string(r.Username),
	}
	if err := checkExtraInfoKey(r.Item); err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrBadRequest))
	}
	buf, err := json.Marshal(r.Data)
	if err != nil {
		// This should not be possible as it was only just unmarshalled.
		panic(err)
	}
	id.ExtraInfo = map[string][]string{r.Item: {string(buf)}}
	return translateStoreError(h.h.store.UpdateIdentity(p.Context, &id, store.Update{store.ExtraInfo: store.Set}))
}

func checkExtraInfoKey(key string) error {
	if strings.ContainsAny(key, "./$") {
		return errgo.WithCausef(nil, params.ErrBadRequest, "%q bad key for extra-info", key)
	}
	return nil
}

func (h *apiHandler) userFromIdentity(ctx context.Context, id *store.Identity) (*params.User, error) {
	var publicKeys []*bakery.PublicKey
	if len(id.PublicKeys) > 0 {
		publicKeys = make([]*bakery.PublicKey, len(id.PublicKeys))
		for i, key := range id.PublicKeys {
			pk := key
			publicKeys[i] = &pk
		}
	}
	authID, err := h.h.auth.Identity(ctx, id.Username)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	groups, err := authID.Groups(ctx)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if groups == nil {
		// Ensure that a null list of groups is never sent.
		groups = []string{}
	}
	externalID := string(id.ProviderID)
	var owner params.Username
	if len(id.ProviderInfo["owner"]) > 0 {
		owner = params.Username(id.ProviderInfo["owner"][0])
		externalID = ""
	}
	var sshKeys []string
	if len(id.ExtraInfo["sshkeys"]) > 0 {
		sshKeys = id.ExtraInfo["sshkeys"]
	}
	var lastLogin *time.Time
	if !id.LastLogin.IsZero() {
		lastLogin = &id.LastLogin
	}
	var lastDischarge *time.Time
	if !id.LastDischarge.IsZero() {
		lastDischarge = &id.LastDischarge
	}
	return &params.User{
		Username:      params.Username(id.Username),
		ExternalID:    externalID,
		FullName:      id.Name,
		Email:         id.Email,
		GravatarID:    gravatarHash(id.Email),
		IDPGroups:     groups,
		Owner:         owner,
		PublicKeys:    publicKeys,
		SSHKeys:       sshKeys,
		LastLogin:     lastLogin,
		LastDischarge: lastDischarge,
	}, nil
}

func translateStoreError(err error) error {
	var cause error
	switch errgo.Cause(err) {
	case store.ErrNotFound:
		cause = params.ErrNotFound
	case store.ErrDuplicateUsername:
		cause = params.ErrAlreadyExists
	case nil:
		return nil
	}
	err1 := errgo.WithCausef(err, cause, "").(*errgo.Err)
	err1.SetLocation(1)
	return err1
}
