// Copyright 2014 Canonical Ltd.

package mongodoc

import (
	"time"
)

// Identity holds the in-database representation of a user in the identities
// Mongo collection.
type Identity struct {
	// Username holds the unique name for the user of the system, which is
	// associated to the URL accessed through jaas.io/u/username.
	Username string

	// ExternalID holds a globally unique name for the user.
	ExternalID string `bson:"external_id,omitempty"`

	// Email holds the email address of the user.
	Email string

	// GravatarID holds the md5 of email address of the user as a gravatar id.
	GravatarID string

	// FullName holds the full name of the user.
	FullName string `bson:"fullname"`

	// Owner holds the username of the owner of this user, if there is one.
	Owner string `bson:",omitempty"`

	// Groups holds a list of group names to which the user belongs.
	Groups []string

	// SSHKeys holds a list of ssh keys owned by the user.
	SSHKeys []string `bson:"ssh_keys,omitempty"`

	// PublicKeys contains a list of public keys associated with this account.
	PublicKeys []PublicKey `bson:"public_keys,omitempty"`

	// ExtraInfo holds additional information about the user that
	// is required by other parts of the system.
	ExtraInfo map[string][]byte `bson:",omitempty" json:",omitempty"`

	// LastLoginTime holds the time of the last login for this identity.
	LastLogin *time.Time `bson:",omitempty"`

	// LastDischargeTime holds the time of the last discharge for this identity.
	LastDischarge *time.Time `bson:",omitempty"`
}

type PublicKey struct {
	Key []byte
}
