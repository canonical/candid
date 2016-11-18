// login is a simple tool that can be used to test the Ubuntu SSO
// discharge login protocol.
package main

import (
	"encoding/json"
	"flag"
	"log"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/ussodischarge"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"
)

var (
	email    = flag.String("email", "", "email")
	insecure = flag.Bool("insecure", false, "get public key over insecure connections")
	password = flag.String("password", "", "password")
	otp      = flag.String("otp", "", "verification code")
	url      = flag.String("url", "https://api.jujucharms.com/identity", "identity url")
)

func main() {
	log.SetFlags(log.Flags() | log.Llongfile)
	flag.Parse()
	tpl := httpbakery.NewThirdPartyLocator(nil, nil)
	if *insecure {
		tpl.AllowInsecure()
	}
	bs, err := bakery.NewService(bakery.NewServiceParams{
		Location: "test",
		Locator:  tpl,
	})
	if err != nil {
		log.Fatalf("cannot create bakery: %s", err)
	}
	m, err := bs.NewMacaroon(bakery.LatestVersion, []checkers.Caveat{{
		Condition: "is-authenticated-user",
		Location:  *url,
	}})
	if err != nil {
		log.Fatalf("cannot make macaroon: %s", err)
	}

	client := httpbakery.NewClient()
	lms, err := login(client, *url+"/v1/idp/usso_discharge/login")
	if err != nil {
		log.Fatalf("cannot login: %s", err)
	}
	client.WebPageVisitor = httpbakery.NewMultiVisitor(
		ussodischarge.NewVisitor(func(*httpbakery.Client, string) (macaroon.Slice, error) {
			return lms, nil
		}),
	)
	ms, err := client.DischargeAll(m)
	if err != nil {
		log.Fatalf("cannot discharge macaroon: %s", err)
	}
	d := checkers.InferDeclared(ms)
	if err := bs.Check(ms, checkers.New(
		d,
		checkers.TimeBefore,
	)); err != nil {
		log.Fatalf("invalid macaroon discharge: %s", err)
	}
}

func login(doer httprequest.Doer, url string) (macaroon.Slice, error) {
	m, err := ussodischarge.Macaroon(doer, url)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	d := &ussodischarge.Discharger{
		Email:    *email,
		Password: *password,
		OTP:      *otp,
		Doer:     doer,
	}
	ms, err := d.DischargeAll(m)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	buf, err := json.MarshalIndent(ms, "\t", "")
	log.Printf("ms:\n%s", buf)
	return ms, nil
}
