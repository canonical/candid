package main

import (
	"flag"
	"fmt"
	"log"

	"git.openstack.org/stackforge/golang-client.git/openstack"
	"gopkg.in/goose.v1/identity"
)

var (
	url        = flag.String("url", "https://keystone.canonistack.canonical.com:443/v2.0/tokens", "URL of tokens endpoint at keystone server")
	username   = flag.String("username", "demo", "username")
	password   = flag.String("password", "devstack", "password")
	tenant     = flag.String("tenant", "", "tenant name")
	stackforge = flag.Bool("stackforge", false, "use stackforge client.")
)

func main() {
	flag.Parse()
	if *stackforge {
		loginStackforge()
		return
	}
	loginGoose()
}

func loginGoose() {
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

func loginStackforge() {
	*openstack.Debug = true
	ar, err := openstack.DoAuthRequest(openstack.AuthOpts{
		AuthUrl:  *url,
		Username: *username,
		Password: *password,
		Project:  *tenant,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", ar)
}
