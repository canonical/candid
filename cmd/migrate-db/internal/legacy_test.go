// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package internal_test

import (
	"context"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/juju/mgotest"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	mgo "gopkg.in/mgo.v2"

	"github.com/canonical/candid/cmd/migrate-db/internal"
	"github.com/canonical/candid/cmd/migrate-db/internal/mongodoc"
	"github.com/canonical/candid/internal/auth"
	"github.com/canonical/candid/store"
	"github.com/canonical/candid/store/memstore"
)

func TestLegacySource(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	ctx := context.Background()
	db, err := mgotest.New()
	if errgo.Cause(err) == mgotest.ErrDisabled {
		c.Skip("mmgotest disabled")
	}
	c.Assert(err, qt.Equals, nil)
	defer db.Close()
	// mgotest sets the SocketTimout to 1s. Restore it back to the
	// default value.
	db.Session.SetSocketTimeout(time.Minute)

	t1 := time.Now().Add(-1 * time.Minute).Round(time.Millisecond)
	t2 := t1.Add(-1 * time.Minute).Round(time.Millisecond)
	insert(c, db.Database, &mongodoc.Identity{
		Username:      "test1",
		ExternalID:    "https://login.ubuntu.com/+id/AAAAAA",
		Email:         "test1@example.com",
		GravatarID:    "f261adc7c891836ecc58c62fb80c6e34",
		FullName:      "Test User",
		Groups:        []string{"group1", "group2"},
		SSHKeys:       []string{"ssh-rsa AAAAAAAAAAAAAAAAAAAAAAAAAAAA== test@test"},
		LastLogin:     &t1,
		LastDischarge: &t2,
	})

	k1 := bakery.MustGenerateKey()
	insert(c, db.Database, &mongodoc.Identity{
		Username: "test2@admin@idm",
		Owner:    "admin@idm",
		Groups:   []string{"admin@idm", "grouplist@idm", "sshkeygetter@idm"},
		PublicKeys: []mongodoc.PublicKey{{
			Key: k1.Public.Key[:],
		}},
	})

	insert(c, db.Database, &mongodoc.Identity{
		Username:   "test3@azure",
		ExternalID: "openid-connect:https://login.live.com:AAAAAAAAAAAAAAAAAAAAAIDX0brimGEivOk0995Z2FB",
		Email:      "test3@example.com",
		FullName:   "Test User III",
	})

	insert(c, db.Database, &mongodoc.Identity{
		Username:   "AAAAAAA@usso",
		ExternalID: "usso-openid:AAAAAAA",
		Email:      "test4@example.com",
		FullName:   "Test User IV",
	})

	st := memstore.NewStore()
	err = internal.Copy(ctx, st, internal.NewLegacySource(db.Database))
	c.Assert(err, qt.Equals, nil)
	identity1 := store.Identity{
		Username: "test1",
	}
	err = st.Identity(ctx, &identity1)
	c.Assert(err, qt.Equals, nil)
	normalize(&identity1)
	c.Assert(identity1, qt.DeepEquals, store.Identity{
		ProviderID:    "usso:https://login.ubuntu.com/+id/AAAAAA",
		Username:      "test1",
		Email:         "test1@example.com",
		Name:          "Test User",
		Groups:        []string{"group1", "group2"},
		LastLogin:     t1,
		LastDischarge: t2,
		ExtraInfo: map[string][]string{
			"sshkeys": {"ssh-rsa AAAAAAAAAAAAAAAAAAAAAAAAAAAA== test@test"},
		},
	})

	identity2 := store.Identity{
		Username: "test2@admin@idm",
	}
	err = st.Identity(ctx, &identity2)
	c.Assert(err, qt.Equals, nil)
	normalize(&identity2)
	c.Assert(identity2, qt.DeepEquals, store.Identity{
		ProviderID: "idm:test2@admin@idm",
		Username:   "test2@admin@idm",
		Groups:     []string{"admin@candid", "grouplist@candid", "sshkeygetter@candid"},
		PublicKeys: []bakery.PublicKey{k1.Public},
		Owner:      auth.AdminProviderID,
	})

	identity3 := store.Identity{
		Username: "test3@azure",
	}
	err = st.Identity(ctx, &identity3)
	c.Assert(err, qt.Equals, nil)
	normalize(&identity3)
	c.Assert(identity3, qt.DeepEquals, store.Identity{
		ProviderID: "azure:https://login.live.com:AAAAAAAAAAAAAAAAAAAAAIDX0brimGEivOk0995Z2FB",
		Username:   "test3@azure",
		Name:       "Test User III",
		Email:      "test3@example.com",
	})

	identity4 := store.Identity{
		Username: "AAAAAAA@usso",
	}
	err = st.Identity(ctx, &identity4)
	c.Assert(err, qt.Equals, nil)
	normalize(&identity4)
	c.Assert(identity4, qt.DeepEquals, store.Identity{
		ProviderID: "usso_macaroon:AAAAAAA",
		Username:   "AAAAAAA@usso",
		Name:       "Test User IV",
		Email:      "test4@example.com",
	})
}

func insert(c *qt.C, db *mgo.Database, identity *mongodoc.Identity) {
	err := db.C("identities").Insert(identity)
	c.Assert(err, qt.Equals, nil)
}
