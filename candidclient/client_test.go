package candidclient_test

import (
	"context"
	"sort"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery/identchecker"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery"
	"gopkg.in/errgo.v1"

	"github.com/canonical/candid/candidclient"
	"github.com/canonical/candid/candidtest"
)

func TestIdentityClient(t *testing.T) {
	c := qt.New(t)
	defer c.Done()
	srv := candidtest.NewServer()
	srv.AddUser("bob", "alice", "charlie")
	testIdentityClient(c,
		srv.CandidClient("bob"),
		srv.Client("bob"),
		"bob", "bob", []string{"alice", "charlie"},
	)
}

func TestIdentityClientWithDomainStrip(t *testing.T) {
	c := qt.New(t)
	defer c.Done()
	srv := candidtest.NewServer()
	srv.AddUser("bob@usso", "alice@usso", "charlie@elsewhere")
	testIdentityClient(c,
		candidclient.StripDomain(srv.CandidClient("bob@usso"), "usso"),
		srv.Client("bob@usso"),
		"bob@usso", "bob", []string{"alice", "charlie@elsewhere"},
	)
}

func TestIdentityClientWithDomainStripNoDomains(t *testing.T) {
	c := qt.New(t)
	defer c.Done()
	srv := candidtest.NewServer()
	srv.AddUser("bob", "alice", "charlie")
	testIdentityClient(c,
		candidclient.StripDomain(srv.CandidClient("bob"), "usso"),
		srv.Client("bob"),
		"bob", "bob", []string{"alice", "charlie"},
	)
}

// testIdentityClient tests that the given identity client can be used to
// create a third party caveat that when discharged provides
// an Identity with the given id, user name and groups.
func testIdentityClient(c *qt.C, candidClient identchecker.IdentityClient, bclient *httpbakery.Client, expectId, expectUser string, expectGroups []string) {
	kr := httpbakery.NewThirdPartyLocator(nil, nil)
	kr.AllowInsecure()
	b := identchecker.NewBakery(identchecker.BakeryParams{
		Locator:        kr,
		Key:            bakery.MustGenerateKey(),
		IdentityClient: candidClient,
	})
	_, authErr := b.Checker.Auth().Allow(context.TODO(), identchecker.LoginOp)
	derr := errgo.Cause(authErr).(*bakery.DischargeRequiredError)

	m, err := b.Oven.NewMacaroon(context.TODO(), bakery.LatestVersion, derr.Caveats, derr.Ops...)
	c.Assert(err, qt.IsNil)

	ms, err := bclient.DischargeAll(context.TODO(), m)
	c.Assert(err, qt.IsNil)

	// Make sure that the macaroon discharged correctly and that it
	// has the right declared caveats.
	authInfo, err := b.Checker.Auth(ms).Allow(context.TODO(), identchecker.LoginOp)
	c.Assert(err, qt.IsNil)

	c.Assert(authInfo.Identity, qt.Not(qt.IsNil))
	c.Assert(authInfo.Identity.Id(), qt.Equals, expectId)
	c.Assert(authInfo.Identity.Domain(), qt.Equals, "")

	user := authInfo.Identity.(candidclient.Identity)

	u, err := user.Username()
	c.Assert(err, qt.IsNil)
	c.Assert(u, qt.Equals, expectUser)
	ok, err := user.Allow(context.TODO(), []string{expectGroups[0]})
	c.Assert(err, qt.IsNil)
	c.Assert(ok, qt.Equals, true)

	groups, err := user.Groups()
	c.Assert(err, qt.IsNil)
	sort.Strings(groups)
	c.Assert(groups, qt.DeepEquals, expectGroups)
}
