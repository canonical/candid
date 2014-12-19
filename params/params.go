// Copyright 2014 Canonical Ltd.

package params

const (
	ProtocolOpenID20 = "openid20"

	// OpenID2.0 settings.
	// See http://openid.net/specs/openid-authentication-2_0.html for details.
	OpenID20AssociationHandle = "openid.assoc_handle"
	OpenID20LoginURL          = "openid.login_url"
	OpenID20Namespace         = "openid.ns"
	OpenID20ReturnTo          = "openid.return_to"
)

// IdentityProvider represents a registered identity provider in the system.
type IdentityProvider struct {
	Name     string                 `json:"name"`
	Protocol string                 `json:"protocol"`
	Settings map[string]interface{} `json:"settings"`
}

// User represents a user in the system.
type User struct {
	UserName         string `json:"username"`
	IdentityProvider string `json:"identity_provider"`
}
