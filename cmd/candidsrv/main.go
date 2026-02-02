// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/gorilla/handlers"
	"github.com/juju/loggo"
	_ "github.com/lib/pq"
	"golang.org/x/net/http/httpproxy"
	"gopkg.in/errgo.v1"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/canonical/candid"
	"github.com/canonical/candid/config"
	"github.com/canonical/candid/idp"
	_ "github.com/canonical/candid/idp/adfs"
	_ "github.com/canonical/candid/idp/agent"
	_ "github.com/canonical/candid/idp/azure"
	_ "github.com/canonical/candid/idp/google"
	_ "github.com/canonical/candid/idp/keycloak"
	_ "github.com/canonical/candid/idp/keystone"
	_ "github.com/canonical/candid/idp/ldap"
	_ "github.com/canonical/candid/idp/static"
	"github.com/canonical/candid/idp/usso"
	_ "github.com/canonical/candid/idp/usso/ussodischarge"
	_ "github.com/canonical/candid/idp/usso/ussooauth"
	"github.com/canonical/candid/internal/mfa"
	_ "github.com/canonical/candid/store/memstore"
	_ "github.com/canonical/candid/store/mgostore"
	_ "github.com/canonical/candid/store/sqlstore"
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
		logger.Infof("configuring HTTP(S) proxy %s", conf.HTTPProxy)
		t, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return errgo.New("http-proxy configured, but DefaultTransport cannot be modified.")
		}
		pcfg := httpproxy.Config{
			HTTPProxy:  conf.HTTPProxy,
			HTTPSProxy: conf.HTTPProxy,
			NoProxy:    conf.NoProxy,
		}
		pf := pcfg.ProxyFunc()
		t.Proxy = func(req *http.Request) (*url.URL, error) {
			return pf(req.URL)
		}
	}
	backend, err := conf.Storage.NewBackend()
	if err != nil {
		return errgo.Mask(err)
	}
	defer backend.Close()
	return serveIdentity(conf, candid.ServerParams{
		Store:                   backend.Store(),
		ProviderDataStore:       backend.ProviderDataStore(),
		MeetingStore:            backend.MeetingStore(),
		RootKeyStore:            backend.BakeryRootKeyStore(),
		DebugStatusCheckerFuncs: backend.DebugStatusCheckerFuncs(),
		ACLStore:                backend.ACLStore(),
	})
}

const (
	hstsMaxAgeFormat      = "max-age=%d"
	hstsIncludeSubDomains = "; includeSubDomains"
)

// hstsMiddleware adds HSTS headers when configured.
func hstsMiddleware(next http.Handler, maxAge int, includeSubDomains bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerParams := fmt.Sprintf(hstsMaxAgeFormat, maxAge)
		if includeSubDomains {
			// Capital 'S and D' per RFC 6797
			headerParams += hstsIncludeSubDomains
		}
		w.Header().Add("Strict-Transport-Security", headerParams)
		next.ServeHTTP(w, r)
	})
}

func serveIdentity(conf *config.Config, params candid.ServerParams) error {
	logger.Infof("setting up the identity server")
	params.IdentityProviders = defaultIDPs
	if len(conf.IdentityProviders) > 0 {
		params.IdentityProviders = make([]idp.IdentityProvider, len(conf.IdentityProviders))
		for i, idp := range conf.IdentityProviders {
			params.IdentityProviders[i] = idp.IdentityProvider
		}
	}
	params.StaticFileSystem = staticFS(conf.ResourcePath)

	var err error
	params.Template, err = loadTemplates(conf.ResourcePath)
	if err != nil {
		return errgo.Notef(err, "cannot parse templates")
	}

	if conf.MFARPDisplayName != "" && conf.MFARPID != "" && conf.MFARPOrigin != "" {
		authenticator, err := mfa.NewAuthenticator(conf.MFARPID, conf.MFARPDisplayName, conf.MFARPOrigin)
		if err != nil {
			return errgo.Mask(err)
		}
		params.MFAAuthenticator = authenticator
	} else {
		logger.Infof("multi-factor authentication not enabled")
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
	params.RedirectLoginTrustedURLs = conf.RedirectLoginTrustedURLs
	params.RedirectLoginTrustedDomains = conf.RedirectLoginTrustedDomains
	params.APIMacaroonTimeout = conf.APIMacaroonTimeout.Duration
	params.DischargeMacaroonTimeout = conf.DischargeMacaroonTimeout.Duration
	params.DischargeTokenTimeout = conf.DischargeTokenTimeout.Duration
	params.SkipLocationForCookiePaths = conf.SkipLocationForCookiePaths
	params.EnableEmailLogin = conf.EnableEmailLogin
	srv, err := candid.NewServer(
		params,
		candid.V1,
		candid.Debug,
		candid.Discharger,
	)
	if err != nil {
		return errgo.Notef(err, "cannot create new server at %q", conf.ListenAddress)
	}
	defer srv.Close()

	// Cast the Server to an http.Handler so that it can be
	// optionally wrapped by the logging handler below.
	var server http.Handler = srv

	// Add HSTS middleware if configured.
	if conf.HSTSMaxAge > 0 {
		server = hstsMiddleware(server, conf.HSTSMaxAge, conf.HSTSIncludeSubdomains)
	}

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
		Addr:      conf.ListenAddress,
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
	usso.NewIdentityProvider(usso.Params{}),
}
