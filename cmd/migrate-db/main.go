// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	mgo "github.com/juju/mgo/v2"
	_ "github.com/lib/pq"
	errgo "gopkg.in/errgo.v1"

	"github.com/canonical/candid/v2/cmd/migrate-db/internal"
	"github.com/canonical/candid/v2/store"
	"github.com/canonical/candid/v2/store/mgostore"
	"github.com/canonical/candid/v2/store/sqlstore"
)

var (
	from = flag.String("from", "legacy:mongodb://localhost/identity", "store `specification` to copy the identities from.")
	to   = flag.String("to", "mgo:mongodb://localhost/idm", "store `specification` to copy the identities to.")
)

func main() {
	flag.Usage = usage
	flag.Parse()
	if err := migrate(context.Background()); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprint(os.Stderr, `
Migrate all of the identities from one store to another. Stores are
specified by a string containing the store type, a colon, and connection
information specific to the store type. For the -from store the valid
prefixes are:

	"legacy" - old style mgo based store
	"mgo" - new style mgo based store 
	"postgres" - postgres based store

The -to store only supports "mgo" and "postgres".

For "legacy" and "mgo" type stores the connection string is a mgo URL
(see https://godoc.org/gopkg.in/mgo.v2#Dial). For "postgres" type
stores the connection string is as documented in
https://godoc.org/github.com/lib/pq.

`)
	flag.PrintDefaults()
}

func migrate(ctx context.Context) error {
	var source internal.Source
	type_, addr := internal.SplitStoreSpecification(*from)
	switch type_ {
	case "legacy":
		s, err := mgo.Dial(addr)
		if err != nil {
			return errgo.Notef(err, "cannot connnect to mongodb server")
		}
		defer s.Close()
		source = internal.NewLegacySource(s.DB(""))
	case "mgo":
		s, err := mgo.Dial(addr)
		if err != nil {
			return errgo.Notef(err, "cannot connnect to mongodb server")
		}
		defer s.Close()
		backend, err := mgostore.NewBackend(s.DB(""))
		if err != nil {
			return errgo.Notef(err, "cannot initialize mgo store")
		}
		defer backend.Close()
		source = internal.NewStoreSource(ctx, backend.Store())
	case "postgres":
		sqldb, err := sql.Open("postgres", addr)
		if err != nil {
			return errgo.Notef(err, "cannot connect to postgresql server")
		}
		defer sqldb.Close()
		backend, err := sqlstore.NewBackend("postgres", sqldb)
		if err != nil {
			return errgo.Notef(err, "cannot initialize postgresql database")
		}
		defer backend.Close()
		source = internal.NewStoreSource(ctx, backend.Store())
	default:
		return errgo.Newf("invalid source type %q", type_)
	}

	var store store.Store
	type_, addr = internal.SplitStoreSpecification(*to)
	switch type_ {
	case "mgo":
		s, err := mgo.Dial(addr)
		if err != nil {
			return errgo.Notef(err, "cannot connnect to mongodb server")
		}
		defer s.Close()
		backend, err := mgostore.NewBackend(s.DB(""))
		if err != nil {
			return errgo.Notef(err, "cannot initialize mgo store")
		}
		defer backend.Close()
		store = backend.Store()
	case "postgres":
		sqldb, err := sql.Open("postgres", addr)
		if err != nil {
			return errgo.Notef(err, "cannot connect to postgresql server")
		}
		defer sqldb.Close()
		backend, err := sqlstore.NewBackend("postgres", sqldb)
		if err != nil {
			return errgo.Notef(err, "cannot initialize postgresql database")
		}
		defer backend.Close()
		store = backend.Store()
	default:
		return errgo.Newf("invalid destination type %q", type_)
	}

	ctx, close := store.Context(ctx)
	defer close()

	return errgo.Mask(internal.Copy(ctx, store, source))
}
