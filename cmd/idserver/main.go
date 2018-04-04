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

	"github.com/CanonicalLtd/blues-identity"
	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	_ "github.com/CanonicalLtd/blues-identity/idp/agent"
	_ "github.com/CanonicalLtd/blues-identity/idp/azure"
	_ "github.com/CanonicalLtd/blues-identity/idp/google"
	_ "github.com/CanonicalLtd/blues-identity/idp/keystone"
	_ "github.com/CanonicalLtd/blues-identity/idp/ldap"
	"github.com/CanonicalLtd/blues-identity/idp/usso"
	_ "github.com/CanonicalLtd/blues-identity/idp/usso/ussodischarge"
	"github.com/CanonicalLtd/blues-identity/idp/usso/ussooauth"
	"github.com/CanonicalLtd/blues-identity/mgostore"
	"github.com/CanonicalLtd/blues-identity/sqlstore"
)

var (
	logger        = loggo.GetLogger("idserver")
	loggingConfig = flag.String("logging-config", "", "specify log levels for modules e.g. <root>=TRACE")
	resourcePath  = flag.String("resource-path", "", "specify the path for resource files")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options] <config path>\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
	}
	if *loggingConfig != "" {
		if err := loggo.ConfigureLoggers(*loggingConfig); err != nil {
			fmt.Fprintf(os.Stderr, "cannot configure loggers: %v", err)
			os.Exit(1)
		}
	} else {
		loggo.GetLogger("").SetLogLevel(loggo.INFO)
	}
	if err := serve(flag.Arg(0)); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// serve starts the identity service.
func serve(confPath string) error {
	logger.Infof("reading configuration")
	conf, err := config.Read(confPath)
	if err != nil {
		return errgo.Notef(err, "cannot read config file %q", confPath)
	}

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

	// If a resource path is specified on the commandline, it takes precedence
	// over the one in the config.
	if *resourcePath == "" {
		if conf.ResourcePath != "" {
			*resourcePath = conf.ResourcePath
		} else {
			*resourcePath = "."
		}
	}
	params.StaticFileSystem = http.Dir(filepath.Join(*resourcePath, "static"))

	var err error
	params.Template, err = template.New("").ParseGlob(filepath.Join(*resourcePath, "templates", "*"))
	if err != nil {
		return errgo.Notef(err, "cannot parse templates")
	}

	params.AuthUsername = conf.AuthUsername
	params.AuthPassword = conf.AuthPassword
	params.Key = &bakery.KeyPair{
		Private: *conf.PrivateKey,
		Public:  *conf.PublicKey,
	}
	params.WaitTimeout = conf.WaitTimeout.Duration
	params.Location = conf.Location
	params.PrivateAddr = conf.PrivateAddr
	params.DebugTeams = conf.DebugTeams
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

	if conf.TLSConfig() != nil {
		return httpServer.ListenAndServeTLS("", "")
	}
	return httpServer.ListenAndServe()
}

var defaultIDPs = []idp.IdentityProvider{
	usso.IdentityProvider,
	ussooauth.IdentityProvider,
}
