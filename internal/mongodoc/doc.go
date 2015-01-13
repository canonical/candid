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

	// UserName holds the unique name for the user of the system, which is
	// associated to the URL accessed through jaas.io/u/username.
	UserName string

	// ExternalID holds a globally unique name for the user.
	ExternalID string `bson:"external_id"`

	// Email holds the email address of the user.
	Email string

	// FullName holds the full name of the user.
	FullName string `bson:"fullname"`

	// Groups holds a list of group names to which the user belongs.
	Groups []string
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
