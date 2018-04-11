// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package main

import (
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/handlers"
	"github.com/juju/loggo"
	_ "github.com/lib/pq"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/mgorootkeystore"
	"gopkg.in/macaroon-bakery.v2/bakery/postgresrootkeystore"
	"gopkg.in/mgo.v2"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/CanonicalLtd/candid"
	"github.com/CanonicalLtd/candid/config"
	"github.com/CanonicalLtd/candid/idp"
	_ "github.com/CanonicalLtd/candid/idp/agent"
	_ "github.com/CanonicalLtd/candid/idp/azure"
	_ "github.com/CanonicalLtd/candid/idp/google"
	_ "github.com/CanonicalLtd/candid/idp/keystone"
	_ "github.com/CanonicalLtd/candid/idp/ldap"
	"github.com/CanonicalLtd/candid/idp/usso"
	_ "github.com/CanonicalLtd/candid/idp/usso/ussodischarge"
	"github.com/CanonicalLtd/candid/idp/usso/ussooauth"
	"github.com/CanonicalLtd/candid/mgostore"
	"github.com/CanonicalLtd/candid/sqlstore"
)

var logger = loggo.GetLogger("candidsrv")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options] <config path>\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		exit(2)
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
	}
	confPath := flag.Arg(0)
	conf, err := config.Read(confPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "STOP cannot read configuration: %v\n", err)
		exit(2)
	}
	if err := loggo.ConfigureLoggers(conf.LoggingConfig); err != nil {
		fmt.Fprintf(os.Stderr, "STOP cannot configure loggers: %v", err)
		exit(2)
	}
	if err := serve(conf); err != nil {
		fmt.Fprintf(os.Stderr, "STOP %v\n", err)
		exit(1)
	}
	fmt.Fprintln(os.Stderr, "STOP no error, weirdly")
	exit(0)
}

// exit calls os.Exit, first sleeping for a bit to work
// around an outrageous systemd bug which causes
// final output lines to be lost if we exit immediately.
// See https://github.com/systemd/systemd/issues/2913
//
// Note: exit status 2 implies we won't restart the service.
func exit(code int) {
	time.Sleep(200 * time.Millisecond)
	os.Exit(code)
}

// serve starts the identity service.
func serve(conf *config.Config) error {

	if conf.HTTPProxy != "" {
		os.Setenv("HTTP_PROXY", conf.HTTPProxy)
	}
	if conf.NoProxy != "" {
		os.Setenv("NO_PROXY", conf.NoProxy)
	}

	switch {
	case conf.MongoAddr != "":
		return serveMgoServer(conf)
	case conf.PostgresConnectionString != "":
		return servePostgresServer(conf)
	default:
		// This should be detected when reading the config earlier
		return errgo.Newf("no database configured")
	}
}

func serveMgoServer(conf *config.Config) error {
	logger.Infof("connecting to mongo")
	session, err := mgo.Dial(conf.MongoAddr)
	if err != nil {
		return errgo.Notef(err, "cannot dial mongo at %q", conf.MongoAddr)
	}
	defer session.Close()
	db := session.DB("identity")
	database, err := mgostore.NewDatabase(db)
	if err != nil {
		return errgo.Notef(err, "cannot initialise database")
	}
	defer database.Close()
	return serveIdentity(conf, identity.ServerParams{
		Store:             database.Store(),
		ProviderDataStore: database.ProviderDataStore(),
		MeetingStore:      database.MeetingStore(),
		RootKeyStore: database.BakeryRootKeyStore(mgorootkeystore.Policy{
			ExpiryDuration: 365 * 24 * time.Hour,
		}),
		DebugStatusCheckerFuncs: database.DebugStatusCheckerFuncs(),
	})
}

func servePostgresServer(conf *config.Config) error {
	logger.Infof("connecting to postgresql")
	db, err := sql.Open("postgres", conf.PostgresConnectionString)
	if err != nil {
		return errgo.Notef(err, "cannot connect to database")
	}
	database, err := sqlstore.NewDatabase("postgres", db)
	if err != nil {
		return errgo.Notef(err, "cannot initialise database")
	}
	defer database.Close()
	rootkeys := postgresrootkeystore.NewRootKeys(db, "rootkeys", 1000)
	defer rootkeys.Close()
	return serveIdentity(conf, identity.ServerParams{
		Store:             database.Store(),
		ProviderDataStore: database.ProviderDataStore(),
		MeetingStore:      database.MeetingStore(),
		RootKeyStore: rootkeys.NewStore(postgresrootkeystore.Policy{
			ExpiryDuration: 365 * 24 * time.Hour,
		}),
	})
}

func serveIdentity(conf *config.Config, params identity.ServerParams) error {
	logger.Infof("setting up the identity server")
	params.IdentityProviders = defaultIDPs
	if len(conf.IdentityProviders) > 0 {
		params.IdentityProviders = make([]idp.IdentityProvider, len(conf.IdentityProviders))
		for i, idp := range conf.IdentityProviders {
			params.IdentityProviders[i] = idp.IdentityProvider
		}
	}
	params.StaticFileSystem = http.Dir(filepath.Join(conf.ResourcePath, "static"))

	var err error
	params.Template, err = template.New("").ParseGlob(filepath.Join(conf.ResourcePath, "templates", "*"))
	if err != nil {
		return errgo.Notef(err, "cannot parse templates")
	}

	params.AdminPassword = conf.AdminPassword
	params.Key = &bakery.KeyPair{
		Private: *conf.PrivateKey,
		Public:  *conf.PublicKey,
	}
	params.RendezvousTimeout = conf.RendezvousTimeout.Duration
	params.Location = conf.Location
	params.PrivateAddr = conf.PrivateAddr
	params.AdminAgentPublicKey = conf.AdminAgentPublicKey
	srv, err := identity.NewServer(
		params,
		identity.V1,
		identity.Debug,
		identity.Discharger,
	)
	if err != nil {
		return errgo.Notef(err, "cannot create new server at %q", conf.APIAddr)
	}
	defer srv.Close()

	// Cast the Server to an http.Handler so that it can be
	// optionally wrapped by the logging handler below.
	var server http.Handler = srv

	if conf.AccessLog != "" {
		accesslog := &lumberjack.Logger{
			Filename:   conf.AccessLog,
			MaxSize:    500, // megabytes
			MaxBackups: 3,
			MaxAge:     28, //days
		}
		server = handlers.CombinedLoggingHandler(accesslog, server)
	}

	logger.Infof("starting the identity server")

	httpServer := &http.Server{
		Addr:      conf.APIAddr,
		Handler:   server,
		TLSConfig: conf.TLSConfig(),
	}
	fmt.Println("START")
	if conf.TLSConfig() != nil {
		return httpServer.ListenAndServeTLS("", "")
	}
	return httpServer.ListenAndServe()
}

var defaultIDPs = []idp.IdentityProvider{
	usso.IdentityProvider,
	ussooauth.IdentityProvider,
}
