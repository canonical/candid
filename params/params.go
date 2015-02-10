// Copyright 2014 Canonical Ltd.

package params

import (
	"unicode/utf8"

	"github.com/juju/names"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon.v1"
)

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

// Username represents the name of a user.
type Username string

// UnmarshalText unmarshals a UserName checking it is valid. It
// implements "encoding".TextUnmarshaler.
func (u *Username) UnmarshalText(b []byte) error {
	s := string(b)
	if utf8.RuneCount(b) > 256 {
		return errgo.New("username longer than 256 characters")
	}
	if !names.IsValidUserName(s) {
		return errgo.Newf("illegal username %q", s)
	}
	*u = Username(s)
	return nil
}

// User represents a user in the system.
type User struct {
	Username   Username `json:"username,omitempty"`
	ExternalID string   `json:"external_id"`
	FullName   string   `json:"fullname"`
	Email      string   `json:"email"`
	IDPGroups  []string `json:"idpgroups"`
}

// WaitResponse holds the response from the wait endpoint.
type WaitResponse struct {
	// Macaroon holds the acquired discharge macaroon.
	Macaroon *macaroon.Macaroon
}
