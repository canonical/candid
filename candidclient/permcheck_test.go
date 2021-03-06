// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package candidclient_test

import (
	"testing"
	"time"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/candid/v2/candidclient"
	"github.com/canonical/candid/v2/candidtest"
)

func TestPermChecker(t *testing.T) {
	c := qt.New(t)
	defer c.Done()
	srv := candidtest.NewServer()
	srv.AddUser("server-user", candidtest.GroupListGroup)
	srv.AddUser("alice", "somegroup")

	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: srv.URL.String(),
		Client:  srv.Client("server-user"),
	})
	c.Assert(err, qt.IsNil)

	pc := candidclient.NewPermChecker(client, time.Hour)

	// No permissions always yields false.
	ok, err := pc.Allow("bob", nil)
	c.Assert(err, qt.IsNil)
	c.Assert(ok, qt.Equals, false)

	// If the user isn't found, we return a (false, nil)
	ok, err = pc.Allow("bob", []string{"beatles"})
	c.Assert(err, qt.IsNil)
	c.Assert(ok, qt.Equals, false)

	// If the perms allow everyone, it's ok
	ok, err = pc.Allow("bob", []string{"noone", "everyone"})
	c.Assert(err, qt.IsNil)
	c.Assert(ok, qt.Equals, true)

	// If the perms allow everyone@somewhere, it's ok.
	ok, err = pc.Allow("bob@somewhere", []string{"everyone@somewhere"})
	c.Assert(err, qt.IsNil)
	c.Assert(ok, qt.Equals, true)

	// Check that the everyone@x logic works with multiple @s.
	ok, err = pc.Allow("bob@foo@somewhere@else", []string{"everyone@somewhere@else"})
	c.Assert(err, qt.IsNil)
	c.Assert(ok, qt.Equals, true)

	// Check that we're careful enough about "everyone" as a prefix
	// to a user name.
	ok, err = pc.Allow("bobx", []string{"everyonex"})
	c.Assert(err, qt.IsNil)
	c.Assert(ok, qt.Equals, false)

	// If the perms allow the user itself, it's ok
	ok, err = pc.Allow("bob", []string{"noone", "bob"})
	c.Assert(err, qt.IsNil)
	c.Assert(ok, qt.Equals, true)

	srv.AddUser("bob", "beatles")

	// The group details are currently cached by the client,
	// so the original request will still fail.
	ok, err = pc.Allow("bob", []string{"beatles"})
	c.Assert(err, qt.IsNil)
	c.Assert(ok, qt.Equals, false)

	// Clearing the cache allows it to succeed.
	pc.CacheEvictAll()
	ok, err = pc.Allow("bob", []string{"beatles"})
	c.Assert(err, qt.IsNil)
	c.Assert(ok, qt.Equals, true)
}

func TestGroupCache(t *testing.T) {
	c := qt.New(t)
	defer c.Done()
	srv := candidtest.NewServer()
	srv.AddUser("server-user", candidtest.GroupListGroup)
	srv.AddUser("alice", "somegroup", "othergroup")

	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: srv.URL.String(),
		Client:  srv.Client("server-user"),
	})
	c.Assert(err, qt.IsNil)

	cache := candidclient.NewGroupCache(client, time.Hour)

	// If the user isn't found, we retturn no groups.
	g, err := cache.Groups("bob")
	c.Assert(err, qt.IsNil)
	c.Assert(g, qt.HasLen, 0)

	g, err = cache.Groups("alice")
	c.Assert(err, qt.IsNil)
	c.Assert(g, qt.DeepEquals, []string{"othergroup", "somegroup"})

	srv.AddUser("bob", "beatles")

	// The group details are currently cached by the client,
	// so we'll still see the original group membership.
	g, err = cache.Groups("bob")
	c.Assert(err, qt.IsNil)
	c.Assert(g, qt.HasLen, 0)

	// Clearing the cache allows it to succeed.
	cache.CacheEvictAll()
	g, err = cache.Groups("bob")
	c.Assert(err, qt.IsNil)
	c.Assert(g, qt.DeepEquals, []string{"beatles"})
}
