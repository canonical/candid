// Copyright 2014 Canonical Ltd.

package mongodoc

// Identity holds the in-database representation of a user in the identities
// Mongo collection.
type Identity struct {
	// UUID holds the unique identifier for the identity. The key can be used
	// as a foreign key in other parts that are linked to the identity
	// (for example groups, environments, etc.).
	//
	// If updating an existing entry the UUID should not be changed. omitempty
	// is used to ensure that an attempt to update the UUID cannot be made
	// inadvertently when updating other fields in an Identity document.
	UUID string `bson:"_id,omitempty"`

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
}

// IdentityProvider holds the in-database representation of the an identity provider in the
// IdentityProviders Mongo Collection.
type IdentityProvider struct {
	// Name is the name of the identity provider within the identiy manager system.
	Name string `bson:"_id"`

	// Protocol is the protocol used by the identity provider.
	Protocol string `bson:"protocol"`

	// OpenID 2.0 Settings.

	// LoginURL is the URL to which login is redirected.
	LoginURL string `bson:"login_url,omitempty"`
}

type PublicKey struct {
	Key []byte
}
