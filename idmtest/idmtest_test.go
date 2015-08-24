// Copyright 2015 Canonical Ltd.

package idmtest_test

import (
	"github.com/CanonicalLtd/blues-identity/idmclient"
	idmparams "github.com/CanonicalLtd/blues-identity/params"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon.v1"

	"github.com/CanonicalLtd/blues-identity/idmtest"
)

type suite struct{}

var _ = gc.Suite(&suite{})

func (*suite) TestDischarge(c *gc.C) {
	srv := idmtest.NewServer()
	srv.AddUser("bob")
	client := srv.Client("bob")
	bsvc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: srv,
	})
	c.Assert(err, gc.IsNil)
	m, err := bsvc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  srv.URL.String() + "/v1/discharger",
		Condition: "is-authenticated-user",
	}})
	c.Assert(err, gc.IsNil)

	ms, err := client.DischargeAll(m)
	c.Assert(err, gc.IsNil)

	// Make sure that the macaroon discharged correctly and that it
	// has the right declared caveats.
	attrs, err := bsvc.CheckAny([]macaroon.Slice{ms}, nil, checkers.New())
	c.Assert(err, gc.IsNil)
	c.Assert(attrs, jc.DeepEquals, map[string]string{
		"username": "bob",
	})
}

func (*suite) TestDischargeDefaultUser(c *gc.C) {
	srv := idmtest.NewServer()
	srv.SetDefaultUser("bob")

	bsvc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: srv,
	})
	c.Assert(err, gc.IsNil)
	m, err := bsvc.NewMacaroon("", nil, []checkers.Caveat{{
		Location:  srv.URL.String() + "/v1/discharger",
		Condition: "is-authenticated-user",
	}})
	c.Assert(err, gc.IsNil)

	client := httpbakery.NewClient()
	ms, err := client.DischargeAll(m)
	c.Assert(err, gc.IsNil)

	// Make sure that the macaroon discharged correctly and that it
	// has the right declared caveats.
	attrs, err := bsvc.CheckAny([]macaroon.Slice{ms}, nil, checkers.New())
	c.Assert(err, gc.IsNil)
	c.Assert(attrs, jc.DeepEquals, map[string]string{
		"username": "bob",
	})
}

func (*suite) TestGroups(c *gc.C) {
	srv := idmtest.NewServer()
	srv.AddUser("bob", "beatles", "bobbins")
	srv.AddUser("alice")

	client := idmclient.New(idmclient.NewParams{
		BaseURL: srv.URL.String(),
		Client:  srv.Client("bob"),
	})
	groups, err := client.UserGroups(&idmparams.UserGroupsRequest{
		Username: "bob",
	})
	c.Assert(err, gc.IsNil)
	c.Assert(groups, jc.DeepEquals, []string{"beatles", "bobbins"})

	groups, err = client.UserGroups(&idmparams.UserGroupsRequest{
		Username: "alice",
	})
	c.Assert(err, gc.IsNil)
	c.Assert(groups, gc.HasLen, 0)
}
