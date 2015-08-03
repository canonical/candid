// The putagent command is a temporary stopgap until
// we have proper semantics for adding agents.
//
// It adds an agent to the identity manager under
// the admin name space. It requires the administrator
// password.
//
// NOT FOR PRODUCTION USE
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/CanonicalLtd/blues-identity/idmclient"
	"github.com/CanonicalLtd/blues-identity/params"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
)

var pubKey = flag.String("k", "", "public key of agent")

var usageDoc = `
usage: putadminagent agentname [group...]

This command adds an agent named $agentname@admin@idm
in an identity manager, making it a member of the given groups.
If the -k flag is not specified, a new key pair will be generated
and printed.

The identity manager location and password are taken from
the following environment variables. JUJU_IDM defaults
to the value shown below.

	JUJU_IDM=` + defaultLocation + `
	JUJU_IDM_AUTH=<user>:<password>

NOT FOR PRODUCTION USE!
`[1:]

const defaultLocation = "http://api.jujugui.org/identity"

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageDoc)
		flag.PrintDefaults()
		os.Exit(2)
	}

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
	}
	auth := os.Getenv("JUJU_IDM_AUTH")
	if auth == "" {
		fatalf("$JUJU_IDM_AUTH not set")
	}
	authParts := strings.SplitN(auth, ":", 2)
	if len(authParts) < 2 || authParts[0] == "" {
		fatalf("invalid $JUJU_IDM_AUTH %q; need <user>:<password>", auth)
	}
	location := os.Getenv("JUJU_IDM")
	if location == "" {
		location = "http://api.jujugui.org/identity"
	}
	agentName := flag.Arg(0)
	groups := flag.Args()[1:]
	idm := idmclient.New(idmclient.NewParams{
		BaseURL:      location,
		Client:       httpbakery.NewClient(),
		AuthUsername: authParts[0],
		AuthPassword: authParts[1],
	})
	var key bakery.PublicKey
	if *pubKey != "" {
		if err := key.UnmarshalText([]byte(*pubKey)); err != nil {
			fatalf("invalid public key: %v", err)
		}
	} else {
		keyPair, err := bakery.GenerateKey()
		if err != nil {
			fatalf("cannot generate key: %v", err)
		}
		fmt.Printf("private-key=%s\n", keyPair.Private)
		fmt.Printf("public-key=%s\n", keyPair.Public)
		key = keyPair.Public
	}
	username := agentName + "@admin@idm"
	if err := idm.SetUser(&params.SetUserRequest{
		Username: params.Username(username),
		User: params.User{
			Owner:      "admin@idm",
			IDPGroups:  groups,
			PublicKeys: []*bakery.PublicKey{&key},
		},
	}); err != nil {
		fatalf("cannot put user: %v", err)
	}
	fmt.Printf("user=%s\n", username)
}

func fatalf(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s\n", fmt.Sprintf(f, a...))
	os.Exit(1)
}
