// login is a simple tool that can be used to test the Ubuntu SSO
// discharge login protocol.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1/ussodischarge"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon.v2"
)

var (
	email    = flag.String("email", "", "email")
	insecure = flag.Bool("insecure", false, "get public key over insecure connections")
	password = flag.String("password", "", "password")
	otp      = flag.String("otp", "", "verification code")
	url      = flag.String("url", "https://api.jujucharms.com/identity", "identity url")
)

func main() {
	ctx := context.Background()
	log.SetFlags(log.Flags() | log.Llongfile)
	flag.Parse()
	tpl := httpbakery.NewThirdPartyLocator(nil, nil)
	if *insecure {
		tpl.AllowInsecure()
	}
	key, err := bakery.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	b := identchecker.NewBakery(identchecker.BakeryParams{
		Location: "test",
		Locator:  tpl,
		Key:      key,
	})
	m, err := b.Oven.NewMacaroon(ctx, bakery.LatestVersion, []checkers.Caveat{{
		Condition: "is-authenticated-user",
		Location:  *url,
	}, checkers.TimeBeforeCaveat(time.Now().Add(time.Minute))}, identchecker.LoginOp)
	if err != nil {
		log.Fatalf("cannot make macaroon: %s", err)
	}

	client := httpbakery.NewClient()
	lms, err := login(ctx, client, *url+"/v1/idp/usso_discharge/login")
	if err != nil {
		log.Fatalf("cannot login: %s", err)
	}
	client.AddInteractor(ussodischarge.NewInteractor(func(*httpbakery.Client, string) (macaroon.Slice, error) {
		return lms, nil
	}))
	ms, err := client.DischargeAll(ctx, m)
	if err != nil {
		log.Fatalf("cannot discharge macaroon: %s", err)
	}
	authInfo, err := b.Checker.Auth(ms).Allow(ctx, identchecker.LoginOp)
	if err != nil {
		log.Fatalf("invalid macaroon discharge: %s", err)
	}
	fmt.Printf("success as %v\n", authInfo.Identity.Id())
}

func login(ctx context.Context, doer httprequest.Doer, url string) (macaroon.Slice, error) {
	m, err := ussodischarge.Macaroon(ctx, doer, url)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	d := &ussodischarge.Discharger{
		Email:    *email,
		Password: *password,
		OTP:      *otp,
		Doer:     doer,
	}
	ms, err := d.DischargeAll(ctx, m)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	buf, err := json.MarshalIndent(ms, "\t", "")
	log.Printf("ms:\n%s", buf)
	return ms, nil
}
