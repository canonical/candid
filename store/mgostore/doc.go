// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore

import (
	"time"

	"github.com/juju/loggo"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/candid/store"
)

var logger = loggo.GetLogger("candid.store.mgostore")

// fieldNames provides the name used in the mongo documents for each
// field.
var fieldNames = []string{
	store.ProviderID:    "providerid",
	store.Username:      "username",
	store.Name:          "name",
	store.Email:         "email",
	store.Groups:        "groups",
	store.PublicKeys:    "publickeys",
	store.LastLogin:     "lastlogin",
	store.LastDischarge: "lastdischarge",
	store.ProviderInfo:  "providerinfo",
	store.ExtraInfo:     "extrainfo",
}

// identityDocument holds the in-database representation of a user in the identities
// Mongo collection.
type identityDocument struct {
	// ID is the internal mongodb id for the identity.
	ID bson.ObjectId `bson:"_id"`

	// ProviderID holds the identity provider specific id for the user.
	ProviderID string

	// Username holds the unique name for the user of the system, which is
	// associated to the URL accessed through jaas.io/u/username.
	Username string

	// Email holds the email address of the user.
	Email string

	// Name holds the display name of the user.
	Name string

	// Groups holds a list of group names to which the user belongs.
	Groups []string

	// PublicKeys contains a list of public keys associated with this account.
	PublicKeys_ [][]byte `bson:"publickeys"`

	// LastLoginTime holds the time of the last login for this identity.
	LastLogin time.Time

	// LastDischargeTime holds the time of the last discharge for this identity.
	LastDischarge time.Time

	// ProviderInfo holds additional information about the user that
	// is provider specific.
	ProviderInfo map[string][]string

	// ExtraInfo holds additional information about the user that is
	// required by other parts of the system.
	ExtraInfo map[string][]string
}

// PublicKeys converts the stored public keys into the format used by the
// bakery.
func (d identityDocument) PublicKeys() []bakery.PublicKey {
	pks := make([]bakery.PublicKey, len(d.PublicKeys_))
	i := 0
	for _, data := range d.PublicKeys_ {
		// Filter out any keys that cannot be unmarshaled; there
		// shouldn't be any anyway.
		if err := pks[i].UnmarshalBinary(data); err != nil {
			logger.Warningf("cannot unmarshal public key: %s", err)
			continue
		}
		i++
	}
	return pks[:i]
}

type updateDocument struct {
	Set      bson.D `bson:"$set,omitempty"`
	Unset    bson.D `bson:"$unset,omitempty"`
	AddToSet bson.D `bson:"$addToSet,omitempty"`
	PullAll  bson.D `bson:"$pullAll,omitempty"`
}

func (d *updateDocument) addUpdate(op store.Operation, name string, v interface{}) {
	switch op {
	case store.NoUpdate:
	case store.Set:
		d.Set = append(d.Set, bson.DocElem{name, v})
	case store.Clear:
		d.Unset = append(d.Unset, bson.DocElem{name, ""})
	case store.Push:
		d.AddToSet = append(d.AddToSet, bson.DocElem{name, bson.D{{"$each", v}}})
	case store.Pull:
		d.PullAll = append(d.PullAll, bson.DocElem{name, v})
	default:
		panic("invalid update operation")
	}
}

func (d *updateDocument) IsZero() bool {
	return len(d.Set)+len(d.Unset)+len(d.AddToSet)+len(d.PullAll) == 0
}
