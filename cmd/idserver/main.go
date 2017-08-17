// Copyright 2014 Canonical Ltd.

package main

import (
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/handlers"
	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/mgorootkeystore"
	"gopkg.in/mgo.v2"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/CanonicalLtd/blues-identity"
	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	_ "github.com/CanonicalLtd/blues-identity/idp/agent"
	_ "github.com/CanonicalLtd/blues-identity/idp/azure"
	_ "github.com/CanonicalLtd/blues-identity/idp/google"
	_ "github.com/CanonicalLtd/blues-identity/idp/keystone"
	"github.com/CanonicalLtd/blues-identity/idp/usso"
	_ "github.com/CanonicalLtd/blues-identity/idp/usso/ussodischarge"
	"github.com/CanonicalLtd/blues-identity/idp/usso/ussooauth"
	"github.com/CanonicalLtd/blues-identity/mgostore"
)

var (
	logger        = loggo.GetLogger("idserver")
	loggingConfig = flag.String("logging-config", "", "specify log levels for modules e.g. <root>=TRACE")
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

	logger.Infof("connecting to mongo")
	session, err := mgo.Dial(conf.MongoAddr)
	if err != nil {
		return errgo.Notef(err, "cannot dial mongo at %q", conf.MongoAddr)
	}
	defer session.Close()
	db := session.DB("identity")

	logger.Infof("setting up the identity server")
	idps := defaultIDPs
	if len(conf.IdentityProviders) > 0 {
		idps = make([]idp.IdentityProvider, len(conf.IdentityProviders))
		for i, idp := range conf.IdentityProviders {
			idps[i] = idp.IdentityProvider
		}
	}
	resourcePath := "."
	if conf.ResourcePath != "" {
		resourcePath = conf.ResourcePath
	}
	t, err := template.New("").ParseGlob(filepath.Join(resourcePath, "templates", "*"))
	if err != nil {
		return errgo.Notef(err, "cannot parse templates")
	}
	database, err := mgostore.NewDatabase(db)
	if err != nil {
		return errgo.Notef(err, "cannot create meeting store")
	}
	defer database.Close()

	srv, err := identity.NewServer(
		identity.ServerParams{
			Store:        database.Store(),
			MeetingStore: database.MeetingStore(),
			RootKeyStore: database.BakeryRootKeyStore(mgorootkeystore.Policy{
				ExpiryDuration: 365 * 24 * time.Hour,
			}),
			AuthUsername: conf.AuthUsername,
			AuthPassword: conf.AuthPassword,
			Key: &bakery.KeyPair{
				Private: *conf.PrivateKey,
				Public:  *conf.PublicKey,
			},
			Location:                conf.Location,
			IdentityProviders:       idps,
			PrivateAddr:             conf.PrivateAddr,
			DebugTeams:              conf.DebugTeams,
			AdminAgentPublicKey:     conf.AdminAgentPublicKey,
			StaticFileSystem:        http.Dir(filepath.Join(resourcePath, "static")),
			Template:                t,
			DebugStatusCheckerFuncs: database.DebugStatusCheckerFuncs(),
		},
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
