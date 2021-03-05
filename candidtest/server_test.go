// Copyright 2015 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package candidtest_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"gopkg.in/macaroon-bakery.v3/bakery"
	"gopkg.in/macaroon-bakery.v3/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"github.com/canonical/candid/candidclient"
	"github.com/canonical/candid/candidtest"
	candidparams "github.com/canonical/candid/params"
)

func TestDischarge(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	ctx := context.TODO()
	srv := candidtest.NewServer()
	srv.AddUser("server-user", candidtest.GroupListGroup)
	srv.AddUser("bob", "somegroup")
	client := srv.Client("bob")

	key, err := bakery.GenerateKey()
	c.Assert(err, qt.IsNil)
	b := identchecker.NewBakery(identchecker.BakeryParams{
		Key:            key,
		Locator:        srv,
		IdentityClient: srv.CandidClient("server-user"),
	})
	m, err := b.Oven.NewMacaroon(
		ctx,
		bakery.LatestVersion,
		candidclient.IdentityCaveats(srv.URL.String()),
		identchecker.LoginOp,
	)
	c.Assert(err, qt.IsNil)

	ms, err := client.DischargeAll(ctx, m)
	c.Assert(err, qt.IsNil)

	// Make sure that the macaroon discharged correctly and that it
	// has the right declared caveats.
	authInfo, err := b.Checker.Auth(ms).Allow(ctx, identchecker.LoginOp)
	c.Assert(err, qt.IsNil)
	c.Assert(authInfo.Identity, qt.Not(qt.IsNil))
	ident := authInfo.Identity.(candidclient.Identity)
	c.Assert(ident.Id(), qt.Equals, "bob")
	username, err := ident.Username()
	c.Assert(err, qt.IsNil)
	c.Assert(username, qt.Equals, "bob")
	groups, err := ident.Groups()
	c.Assert(err, qt.IsNil)
	c.Assert(groups, qt.DeepEquals, []string{"somegroup"})
}

func TestDischargeDefaultUser(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	ctx := context.TODO()
	srv := candidtest.NewServer()
	srv.SetDefaultUser("bob")

	key, err := bakery.GenerateKey()
	c.Assert(err, qt.IsNil)
	b := identchecker.NewBakery(identchecker.BakeryParams{
		Key:            key,
		Locator:        srv,
		IdentityClient: srv.CandidClient("server-user"),
	})
	m, err := b.Oven.NewMacaroon(
		ctx,
		bakery.LatestVersion,
		candidclient.IdentityCaveats(srv.URL.String()),
		identchecker.LoginOp,
	)
	c.Assert(err, qt.IsNil)

	client := httpbakery.NewClient()
	ms, err := client.DischargeAll(ctx, m)
	c.Assert(err, qt.IsNil)

	// Make sure that the macaroon discharged correctly and that it
	// has the right declared caveats.
	authInfo, err := b.Checker.Auth(ms).Allow(ctx, identchecker.LoginOp)
	c.Assert(err, qt.IsNil)
	c.Assert(authInfo.Identity, qt.Not(qt.IsNil))
	ident := authInfo.Identity.(candidclient.Identity)
	c.Assert(ident.Id(), qt.Equals, "bob")
	username, err := ident.Username()
	c.Assert(err, qt.IsNil)
	c.Assert(username, qt.Equals, "bob")
	groups, err := ident.Groups()
	c.Assert(err, qt.IsNil)
	c.Assert(groups, qt.HasLen, 0)
}

func TestGroups(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	srv := candidtest.NewServer()
	srv.AddUser("server-user", candidtest.GroupListGroup)
	srv.AddUser("bob", "beatles", "bobbins")
	srv.AddUser("alice")

	client := srv.CandidClient("server-user")
	groups, err := client.UserGroups(context.TODO(), &candidparams.UserGroupsRequest{
		Username: "bob",
	})
	c.Assert(err, qt.IsNil)
	c.Assert(groups, qt.DeepEquals, []string{"beatles", "bobbins"})

	groups, err = client.UserGroups(context.TODO(), &candidparams.UserGroupsRequest{
		Username: "alice",
	})
	c.Assert(err, qt.IsNil)
	c.Assert(groups, qt.HasLen, 0)
}

func TestAddUserWithExistingGroups(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	srv := candidtest.NewServer()
	srv.AddUser("alice", "anteaters")
	srv.AddUser("alice")
	srv.AddUser("alice", "goof", "anteaters")

	client := srv.CandidClient("alice")
	groups, err := client.UserGroups(context.TODO(), &candidparams.UserGroupsRequest{
		Username: "alice",
	})
	c.Assert(err, qt.IsNil)
	c.Assert(groups, qt.DeepEquals, []string{"anteaters", "goof"})
}
