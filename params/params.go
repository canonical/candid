// Copyright 2014 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package params

import (
	"time"
	"unicode/utf8"

	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon.v2"
)

// Username represents the name of a user.
type Username string

// UnmarshalText unmarshals a Username checking it is valid. It
// implements "encoding".TextUnmarshaler.
func (u *Username) UnmarshalText(b []byte) error {
	if utf8.RuneCount(b) > 256 {
		return errgo.New("username longer than 256 characters")
	}
	*u = Username(string(b))
	return nil
}

// AgentLogin contains the claimed identity the agent is attempting to
// use to log in.
type AgentLogin struct {
	Username  Username          `json:"username"`
	PublicKey *bakery.PublicKey `json:"public_key"`
}

// AgentLoginResponse contains the response to an agent login attempt.
type AgentLoginResponse struct {
	AgentLogin bool `json:"agent_login"`
}

// PublicKeyRequest documents the /publickey endpoint. As
// it contains no request information there is no need to ever create
// one.
type PublicKeyRequest struct {
	httprequest.Route `httprequest:"GET /publickey"`
}

// PublicKeyResponse is the response to a PublicKeyRequest.
type PublicKeyResponse struct {
	PublicKey *bakery.PublicKey
}

// LoginMethods holds the response from the /login endpoint
// when called with "Accept: application/json". This enumerates
// the available methods for the client to log in.
type LoginMethods struct {
	// Agent is the endpoint to connect to, if the client wishes to
	// authenticate as an agent.
	Agent string `json:"agent,omitempty"`

	// Interactive is the endpoint to connect to, if the user can
	// interact with the login process.
	Interactive string `json:"interactive,omitempty"`

	// UbuntuSSOOAuth is the endpoint to send a request, signed with
	// UbuntuSSO OAuth credentials, to if the client wishes to use
	// oauth to log in to Identity Manager. Ubuntu SSO uses oauth 1.0.
	UbuntuSSOOAuth string `json:"usso_oauth,omitempty"`

	// UbuntuSSODischarge allows login to be performed by discharging
	// a macaroon with a third-party caveat addressed to Ubuntu SSO.
	UbuntuSSODischarge string `json:"usso_discharge,omitempty"`

	// Form is the endpoint to GET a schema for a login form which
	// can be presented to the user in an interactive manner. The
	// schema will be returned as an environschema.Fields object. The
	// completed form should be POSTed back to the same endpoint.
	Form string `json:"form,omitempty"`
}

// QueryUsersRequest is a request to query the users in the system.
type QueryUsersRequest struct {
	httprequest.Route `httprequest:"GET /v1/u"`

	// ExternalID, if present, matches all identities with the given
	// external ID (there should be a maximum of 1).
	ExternalID string `httprequest:"external_id,form"`

	// EMail, if present, matches all identities with the given email
	// address.
	Email string `httprequest:"email,form"`

	// LastLoginSince, if present, must contain a time marshaled as
	// if using Time.MarshalText. It matches all identies that have a
	// last login time after the given time.
	LastLoginSince string `httprequest:"last-login-since,form"`

	// LastDischargeSince, if present, must contain a time marshaled as
	// if using Time.MarshalText. It matches all identies that have a
	// last discharge time after the given time.
	LastDischargeSince string `httprequest:"last-discharge-since,form"`

	// Owner, if present, matches all agent identities with the given
	// owner.
	Owner string `httprequest:"owner,form"`
}

// UserRequest is a request for the user details of the named user.
type UserRequest struct {
	httprequest.Route `httprequest:"GET /v1/u/:username"`
	Username          Username `httprequest:"username,path"`
}

// User represents a user in the system.
type User struct {
	Username      Username            `json:"username,omitempty"`
	ExternalID    string              `json:"external_id"`
	FullName      string              `json:"fullname"`
	Email         string              `json:"email"`
	GravatarID    string              `json:"gravatar_id"`
	IDPGroups     []string            `json:"idpgroups"`
	Owner         Username            `json:"owner,omitempty"`
	PublicKeys    []*bakery.PublicKey `json:"public_keys"`
	SSHKeys       []string            `json:"ssh_keys"`
	LastLogin     *time.Time          `json:"last_login,omitempty"`
	LastDischarge *time.Time          `json:"last_discharge,omitempty"`
}

// SetUserRequest is a request to set the details of a user.
// This endpoint is no longer functional.
type SetUserRequest struct {
	httprequest.Route `httprequest:"PUT /v1/u/:username"`
	Username          Username `httprequest:"username,path"`
	User              `httprequest:",body"`
}

// CreateAgentRequest is a request to add an agent.
type CreateAgentRequest struct {
	httprequest.Route `httprequest:"POST /v1/u"`
	CreateAgentBody   `httprequest:",body"`
}

// CreateAgentBody holds the body of a CreateAgentRequest.
// There must be at least one public key specified.
type CreateAgentBody struct {
	FullName   string              `json:"fullname"`
	Groups     []string            `json:"idpgroups"`
	PublicKeys []*bakery.PublicKey `json:"public_keys"`

	// A parent agent is one that can create its own agents. A parent
	// agent does not have an owner and so remains a member of the
	// groups it has been allocated irrespective of whether the
	// creating user remains a member. Only users in the write-user
	// ACL can create a parent agent.
	Parent bool `json:"parent,omitempty"`
}

// CreateAgentResponse holds the response from a
// CreateAgentRequest.
type CreateAgentResponse struct {
	Username Username
}

// UserGroupsRequest is a request for the list of groups associated
// with the specified user.
type UserGroupsRequest struct {
	httprequest.Route `httprequest:"GET /v1/u/:username/groups"`
	Username          Username `httprequest:"username,path"`
}

// SetUserGroupsRequest is a request to set the list of groups associated
// with the specified user.
type SetUserGroupsRequest struct {
	httprequest.Route `httprequest:"PUT /v1/u/:username/groups"`
	Username          Username `httprequest:"username,path"`
	Groups            Groups   `httprequest:",body"`
}

// Groups contains a list of group names.
type Groups struct {
	Groups []string `json:"groups"`
}

// ModifyUserGroupsRequest is a request to update the list of groups associated
// with the specified user.
type ModifyUserGroupsRequest struct {
	httprequest.Route `httprequest:"POST /v1/u/:username/groups"`
	Username          Username     `httprequest:"username,path"`
	Groups            ModifyGroups `httprequest:",body"`
}

// ModifyGroups contains a set of group list modifications.
type ModifyGroups struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

// UserIDPGroupsRequest defines the deprecated path for
// UserGroupsRequest. It should no longer be used.
type UserIDPGroupsRequest struct {
	httprequest.Route `httprequest:"GET /v1/u/:username/idpgroups"`
	UserGroupsRequest
}

// UserTokenRequest is a request for a new token to represent the user.
type UserTokenRequest struct {
	httprequest.Route `httprequest:"GET /v1/u/:username/macaroon"`
	Username          Username `httprequest:"username,path"`
}

// VerifyTokenRequest is a request to verify that the provided
// macaroon.Slice is valid and represents a user from identity.
type VerifyTokenRequest struct {
	httprequest.Route `httprequest:"POST /v1/verify"`
	Macaroons         macaroon.Slice `httprequest:",body"`
}

// SSHKeysRequest is a request for the list of ssh keys associated
// with the specified user.
type SSHKeysRequest struct {
	httprequest.Route `httprequest:"GET /v1/u/:username/ssh-keys"`
	Username          Username `httprequest:"username,path"`
}

// UserSSHKeysResponse holds a response to the GET /v1/u/:username/ssh-keys
// containing list of ssh keys associated with the user.
type SSHKeysResponse struct {
	SSHKeys []string `json:"ssh_keys"`
}

// PutSSHKeysRequest is a request to set ssh keys to the list of ssh keys
// associated with the user.
type PutSSHKeysRequest struct {
	httprequest.Route `httprequest:"PUT /v1/u/:username/ssh-keys"`
	Username          Username       `httprequest:"username,path"`
	Body              PutSSHKeysBody `httprequest:",body"`
}

// PutSSHKeysBody holds the body of a PutSSHKeysRequest.
type PutSSHKeysBody struct {
	SSHKeys []string `json:"ssh-keys"`
	Add     bool     `json:"add,omitempty"`
}

// DeleteSSHKeysRequest is a request to remove ssh keys from the list of ssh keys
// associated with the user.
type DeleteSSHKeysRequest struct {
	httprequest.Route `httprequest:"DELETE /v1/u/:username/ssh-keys"`
	Username          Username          `httprequest:"username,path"`
	Body              DeleteSSHKeysBody `httprequest:",body"`
}

// DeleteSSHKeysBody holds the body of a DeleteSSHKeysRequest.
type DeleteSSHKeysBody struct {
	SSHKeys []string `json:"ssh-keys"`
}

// UserExtraInfoRequest is a request for the arbitrary extra information
// stored about the user.
type UserExtraInfoRequest struct {
	httprequest.Route `httprequest:"GET /v1/u/:username/extra-info"`
	Username          Username `httprequest:"username,path"`
}

// SetUserExtraInfoRequest is a request to updated the arbitrary extra
// information stored about the user.
type SetUserExtraInfoRequest struct {
	httprequest.Route `httprequest:"PUT /v1/u/:username/extra-info"`
	Username          Username               `httprequest:"username,path"`
	ExtraInfo         map[string]interface{} `httprequest:",body"`
}

// UserExtraInfoItemRequest is a request for a single element of the
// arbitrary extra information stored about the user.
type UserExtraInfoItemRequest struct {
	httprequest.Route `httprequest:"GET /v1/u/:username/extra-info/:item"`
	Username          Username `httprequest:"username,path"`
	Item              string   `httprequest:"item,path"`
}

// SetUserExtraInfoItemRequest is a request to update a single element of
// the arbitrary extra information stored about the user.
type SetUserExtraInfoItemRequest struct {
	httprequest.Route `httprequest:"PUT /v1/u/:username/extra-info/:item"`
	Username          Username    `httprequest:"username,path"`
	Item              string      `httprequest:"item,path"`
	Data              interface{} `httprequest:",body"`
}

// WhoAmIRequest holds parameters for requesting the current user name.
type WhoAmIRequest struct {
	httprequest.Route `httprequest:"GET /v1/whoami"`
}

// WhoAmIResponse holds information on the currently
// authenticated user.
type WhoAmIResponse struct {
	User string `json:"user"`
}

// DischargeTokenForUserRequest is the request to get a discharge token
// for a specific user.
type DischargeTokenForUserRequest struct {
	httprequest.Route `httprequest:"GET /v1/discharge-token-for-user"`
	Username          Username `httprequest:"username,form"`
}

// DischargeTokenForUserResponse holds the discharge token, in the form
// of a macaroon, for the requested user.
type DischargeTokenForUserResponse struct {
	DischargeToken *bakery.Macaroon
}

// IDPChoice lists available IDPs for authentication.
type IDPChoice struct {
	IDPs []IDPChoiceDetails `json:"idps"`
}

// IDPChoiceDetails provides details about a IDP choice for authentication.
type IDPChoiceDetails struct {
	Domain      string `json:"domain"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Name        string `json:"name"`
	URL         string `json:"url"`
}

// GetUserWithIDRequest is a request for the user details of the user with the
// given ID.
type GetUserWithIDRequest struct {
	httprequest.Route `httprequest:"GET /v1/uid"`
	UserID            string `httprequest:"id,form"`
}

// GetUserGroupsWithIDRequest is a request for the groups of the user with the
// given ID.
type GetUserGroupsWithIDRequest struct {
	httprequest.Route `httprequest:"GET /v1/uid/groups"`
	UserID            string `httprequest:"id,form"`
}

// GroupsResponse is the response to a GetUserGroupsWithIDRequest.
type GroupsResponse struct {
	Groups []string `json:"groups"`
}
