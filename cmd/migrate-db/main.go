// Copyright 2017 Canonical Ltd.

package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"golang.org/x/net/context"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	mgo "gopkg.in/mgo.v2"

	"github.com/CanonicalLtd/blues-identity/cmd/migrate-db/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/mgostore"
	"github.com/CanonicalLtd/blues-identity/store"
)

var (
	server    = flag.String("server", "", "URL of mongodb server.")
	oldDBName = flag.String("old", "identity", "name of legacy identity database")
	newDBName = flag.String("new", "idm", "name of identity database")
)

func main() {
	flag.Parse()
	s, err := mgo.Dial(*server)
	if err != nil {
		log.Printf("cannot connnect to database: %s", err)
		os.Exit(1)
	}
	defer s.Close()
	db, err := mgostore.NewDatabase(s.DB(*newDBName))
	if err != nil {
		log.Printf("cannot initialize database: %s", err)
		os.Exit(1)
	}
	defer db.Close()
	st := db.Store()
	ctx, close := st.Context(context.Background())
	defer close()

	legacy := s.DB(*oldDBName)
	it := legacy.C("identities").Find(nil).Iter()
	var doc mongodoc.Identity
	for it.Next(&doc) {
		err := st.UpdateIdentity(ctx, migrateIdentity(&doc), store.Update{
			store.ProviderID:    store.Set,
			store.Username:      store.Set,
			store.Name:          store.Set,
			store.Email:         store.Set,
			store.Groups:        store.Set,
			store.PublicKeys:    store.Set,
			store.LastLogin:     store.Set,
			store.LastDischarge: store.Set,
			store.ProviderInfo:  store.Set,
			store.ExtraInfo:     store.Set,
		})
		if err != nil {
			log.Printf("cannot update user %s: %s", doc.Username, err)
		}
	}
	err = it.Err()
	if err != nil {
		log.Printf("cannot process identities: %s", err)
		os.Exit(1)
	}
}

func migrateIdentity(doc *mongodoc.Identity) *store.Identity {
	id := &store.Identity{
		Username:   doc.Username,
		ProviderID: providerID(doc),
		Name:       doc.FullName,
		Email:      doc.Email,
		Groups:     doc.Groups,
	}
	if doc.LastLogin != nil {
		id.LastLogin = *doc.LastLogin
	}
	if doc.LastDischarge != nil {
		id.LastDischarge = *doc.LastDischarge
	}
	for _, k := range doc.PublicKeys {
		var key bakery.Key
		copy(key[:], k.Key)
		id.PublicKeys = append(id.PublicKeys, bakery.PublicKey{key})
	}
	if doc.Owner != "" {
		if doc.Owner == "admin@idm" {
			id.ProviderInfo = map[string][]string{
				"owner": []string{string(store.MakeProviderIdentity("idm", "admin@idm")), "admin@idm"},
			}
		} else {
			log.Printf("unrecognised owner for %s (%s), not migrating", doc.Username, doc.Owner)
		}
	}
	if len(doc.SSHKeys) > 0 {
		id.ExtraInfo = map[string][]string{
			"sshkeys": doc.SSHKeys,
		}
	}
	return id
}

func providerID(doc *mongodoc.Identity) store.ProviderIdentity {
	if doc.ExternalID == "" {
		return store.MakeProviderIdentity("idm", doc.Username)
	}
	if strings.HasPrefix(doc.ExternalID, "https://login.ubuntu.com/+id") {
		return store.MakeProviderIdentity("usso", doc.ExternalID)
	}
	if strings.HasPrefix(doc.ExternalID, "openid-connect:") {
		// The only currently used openid provider is azure
		return store.MakeProviderIdentity("azure", strings.TrimPrefix(doc.ExternalID, "openid-connect:"))
	}
	log.Printf("unrecognised external ID: %s", doc.ExternalID)
	return ""
}
