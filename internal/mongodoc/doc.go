// Copyright 2014 Canonical Ltd.

package mongodoc

// Identity holds the in-database representation of a user in the identities
// Mongo collection.
type Identity struct {
	// UUID holds the unique identifier for the identity. The key can be used
	// as a forign key in other parts that are linked to the identity
	// (for example groups, environments, etc.).
	UUID string `bson:"_id"`

	// UserName holds the unique name for the user of the system, which is
	// associated to the URL accessed through jaas.io/u/username.
	UserName string

	// TODO frankban: implement the Identity doc.
}
