// Copyright 2014 Canonical Ltd.

package params

import (
	"unicode/utf8"

	"github.com/juju/names"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
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
	GravatarID string   `json:"gravatar_id"`
	IDPGroups  []string `json:"idpgroups"`
}

// WaitResponse holds the response from the wait endpoint.
type WaitResponse struct {
	// Macaroon holds the acquired discharge macaroon.
	Macaroon *macaroon.Macaroon
}

// LoginMethods holds the response from the login endpoint
// when called with "Accept: application/json". This enumerates
// the available methods for the client to log in.
type LoginMethods struct {
	// Agent is the endpoint to connect to, if the client wishes to
	// authenticate as an agent.
	Agent string `json:"agent,omitempty"`

	// Interactive is the endpoint to connect to, if the user can
	// interact with the login process.
	Interactive string `json:"interactive,omitempty"`

	// UbuntuSSO OAuth is the endpoint to send a request, signed with
	// UbuntuSSO OAuth credentials, to if the client wishes to use
	// oauth to log in to Identity Manager. Ubuntu SSO uses oauth 1.0.
	UbuntuSSOOAuth string `json:"usso_oauth,omitempty"`
}

// AgentLoginRequest is POSTed to the agent login URL to log in as an
// agent. Agents claim an identity along with a public key associated with
// that identity. Any discharge macroons that are generated for an agent
// will contain a third party caveat addressed to "local" that they will have
// to discharge to prove that they hold the private key.
type AgentLoginRequest struct {
	Username  Username          `json:"username"`
	PublicKey *bakery.PublicKey `json:"public_key"`
}
