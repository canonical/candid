// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package v1

import (
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery/identchecker"

	"github.com/canonical/candid/internal/auth"
	"github.com/canonical/candid/params"
)

// opForRequest returns the operation that will be performed
// by the API handler method which takes the given argument r.
// See aclForOp in ../auth/auth.go for the mapping from
// operation to ACLs.
func opForRequest(r interface{}) bakery.Op {
	switch r := r.(type) {
	case *params.QueryUsersRequest:
		if r.Owner != "" {
			return auth.UserOp(params.Username(r.Owner), auth.ActionRead)
		}
		return auth.GlobalOp(auth.ActionRead)
	case *params.UserRequest:
		return auth.UserOp(r.Username, auth.ActionRead)
	case *params.SetUserRequest:
		// TODO require special permissions if the user
		// expiry time is less than some threshold?
		if r.Owner != "" {
			return auth.UserOp(r.Owner, auth.ActionCreateAgent)
		}
		return auth.UserOp(r.Username, auth.ActionWriteAdmin)
	case *params.CreateAgentRequest:
		if r.Parent {
			return auth.GlobalOp(auth.ActionCreateParentAgent)
		}
		return auth.GlobalOp(auth.ActionCreateAgent)
	case *params.UserGroupsRequest:
		return auth.UserOp(r.Username, auth.ActionReadGroups)
	case *params.SetUserGroupsRequest:
		return auth.UserOp(r.Username, auth.ActionWriteGroups)
	case *params.ModifyUserGroupsRequest:
		return auth.UserOp(r.Username, auth.ActionWriteGroups)
	case *params.UserIDPGroupsRequest:
		return auth.UserOp(r.Username, auth.ActionReadGroups)
	case *params.WhoAmIRequest:
		return identchecker.LoginOp
	case *params.SSHKeysRequest:
		return auth.UserOp(r.Username, auth.ActionReadSSHKeys)
	case *params.PutSSHKeysRequest:
		return auth.UserOp(r.Username, auth.ActionWriteSSHKeys)
	case *params.DeleteSSHKeysRequest:
		return auth.UserOp(r.Username, auth.ActionWriteSSHKeys)
	case *params.UserTokenRequest:
		return auth.UserOp(r.Username, auth.ActionReadAdmin)
	case *params.VerifyTokenRequest:
		return auth.GlobalOp(auth.ActionVerify)
	case *params.UserExtraInfoRequest:
		return auth.UserOp(r.Username, auth.ActionReadAdmin)
	case *params.SetUserExtraInfoRequest:
		return auth.UserOp(r.Username, auth.ActionWriteAdmin)
	case *params.UserExtraInfoItemRequest:
		return auth.UserOp(r.Username, auth.ActionReadAdmin)
	case *params.SetUserExtraInfoItemRequest:
		return auth.UserOp(r.Username, auth.ActionWriteAdmin)
	case *params.DischargeTokenForUserRequest:
		return auth.GlobalOp(auth.ActionDischargeFor)
	case *params.GetUserWithIDRequest:
		return auth.UserIDOp(r.UserID, auth.ActionRead)
	case *params.GetUserGroupsWithIDRequest:
		return auth.UserIDOp(r.UserID, auth.ActionReadGroups)
	case *params.ClearUserMFACredentialsRequest:
		return auth.GlobalOp(auth.ActionClearUserMFACredentials)
	default:
		logger.Infof("unknown API argument type %#v", r)
	}
	return bakery.Op{}
}
