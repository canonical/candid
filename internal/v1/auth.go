// Copyright 2017 Canonical Ltd.

package v1

import (
	"github.com/juju/idmclient/params"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"

	"github.com/CanonicalLtd/blues-identity/internal/store"
)

// opForRequest returns the operation that will be performed
// by the API handler method which takes the given argument r.
func opForRequest(r interface{}) bakery.Op {
	switch r := r.(type) {
	case *params.QueryUsersRequest:
		return store.GlobalOp(store.ActionRead)
	case *params.UserRequest:
		return store.UserOp(r.Username, store.ActionRead)
	case *params.SetUserRequest:
		if r.Owner != "" {
			return store.UserOp(r.Owner, store.ActionCreateAgent)
		}
		return store.UserOp(r.Username, store.ActionWriteAdmin)
	case *params.UserGroupsRequest:
		return store.UserOp(r.Username, store.ActionReadGroups)
	case *params.SetUserGroupsRequest:
		return store.UserOp(r.Username, store.ActionWriteGroups)
	case *params.ModifyUserGroupsRequest:
		return store.UserOp(r.Username, store.ActionWriteGroups)
	case *params.UserIDPGroupsRequest:
		return store.UserOp(r.Username, store.ActionReadGroups)
	case *params.WhoAmIRequest:
		return bakery.LoginOp
	case *params.SSHKeysRequest:
		return store.UserOp(r.Username, store.ActionReadSSHKeys)
	case *params.PutSSHKeysRequest:
		return store.UserOp(r.Username, store.ActionWriteSSHKeys)
	case *params.DeleteSSHKeysRequest:
		return store.UserOp(r.Username, store.ActionWriteSSHKeys)
	case *params.UserTokenRequest:
		return store.UserOp(r.Username, store.ActionReadAdmin)
	case *params.VerifyTokenRequest:
		return store.GlobalOp(store.ActionVerify)
	case *params.UserExtraInfoRequest:
		return store.UserOp(r.Username, store.ActionReadAdmin)
	case *params.SetUserExtraInfoRequest:
		return store.UserOp(r.Username, store.ActionWriteAdmin)
	case *params.UserExtraInfoItemRequest:
		return store.UserOp(r.Username, store.ActionReadAdmin)
	case *params.SetUserExtraInfoItemRequest:
		return store.UserOp(r.Username, store.ActionWriteAdmin)
	case *loginRequest:
		return store.GlobalOp(store.ActionLogin)
	case *dischargeTokenForUserRequest:
		return store.GlobalOp(store.ActionDischargeFor)
	case *waitRequest:
		return store.GlobalOp(store.ActionLogin)
	default:
		logger.Infof("unknown API argument type %#v", r)
	}
	return bakery.Op{}
}
