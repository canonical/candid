package main

import (
	"flag"
	"fmt"
	"log"

	"gopkg.in/goose.v1/identity"
)

var (
	url      = flag.String("url", "https://keystone.canonistack.canonical.com:443/v2.0/tokens", "URL of tokens endpoint at keystone server")
	username = flag.String("username", "demo", "username")
	password = flag.String("password", "devstack", "password")
	tenant   = flag.String("tenant", "", "tenant name")
)

func main() {
	flag.Parse()
	auth := identity.NewAuthenticator(identity.AuthUserPass, nil)
	tok, err := auth.Auth(&identity.Credentials{
		URL:        *url,
		User:       *username,
		Secrets:    *password,
		TenantName: *tenant,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", tok)
}
