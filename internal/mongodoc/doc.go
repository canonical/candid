// Copyright 2014 Canonical Ltd.

package mongodoc

// Identity holds the in-database representation of a user in the identities
// Mongo collection.
type Identity struct {
	// UUID holds the unique identifier for the identity. The key can be used
	// as a foreign key in other parts that are linked to the identity
	// (for example groups, environments, etc.).
	UUID string `bson:"_id"`

	// UserName holds the unique name for the user of the system, which is
	// associated to the URL accessed through jaas.io/u/username.
	UserName string

	// IdentityProvider holds the name of the IdentityProvider to use to identify
	// the user.
	IdentityProvider string

	// IdentityToken holds a unique identifier for this use with the identity provider
	IdentityToken string `bson:",omitempty"`

	// TODO frankban: implement the Identity doc.
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
