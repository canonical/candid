// Copyright 2014 Canonical Ltd.

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/handlers"
	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/mgo.v2"
	"gopkg.in/natefinch/lumberjack.v2"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity"
	"github.com/CanonicalLtd/blues-identity/config"
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

	logger.Infof("connecting to mongo")
	session, err := mgo.Dial(conf.MongoAddr)
	if err != nil {
		return errgo.Notef(err, "cannot dial mongo at %q", conf.MongoAddr)
	}
	defer session.Close()
	db := session.DB("identity")

	logger.Infof("setting up the identity server")
	var keypair bakery.KeyPair
	if err := keypair.Private.UnmarshalText([]byte(conf.PrivateKey)); err != nil {
		return errgo.Notef(err, "cannot unmarshal private key")
	}
	if err := keypair.Public.UnmarshalText([]byte(conf.PublicKey)); err != nil {
		return errgo.Notef(err, "cannot unmarshal public key")
	}
	srv, err := identity.NewServer(
		db,
		identity.ServerParams{
			AuthUsername:   conf.AuthUsername,
			AuthPassword:   conf.AuthPassword,
			Key:            &keypair,
			Location:       conf.Location,
			Launchpad:      lpad.Production,
			MaxMgoSessions: conf.MaxMgoSessions,
			RequestTimeout: conf.RequestTimeout.Duration,
		},
		identity.V1,
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
	return http.ListenAndServe(conf.APIAddr, server)
}
