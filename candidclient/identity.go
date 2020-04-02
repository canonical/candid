// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package candidclient

import (
	"context"

	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
)

// Identity represents a Candid identity. It includes bakery.ACLIdentity but
// also includes methods for determining the username and
// enquiring about groups.
//
// Note that currently the Id method just returns the user
// name, but client code should not rely on it doing that - eventually
// it will return an opaque user identifier rather than the user name.
type Identity interface {
	identchecker.ACLIdentity

	// Username returns the user name of the user.
	Username() (string, error)

	// Groups returns all the groups that the user is a member of.
	//
	// Note: use of this method should be avoided if possible, as a user may
	// potentially be in huge numbers of groups.
	Groups() ([]string, error)
}

var _ Identity = (*identity)(nil)

type identity struct {
	client   *Client
	username string
}

// Username implements Identity.Username.
func (id *identity) Username() (string, error) {
	return id.username, nil
}

// Groups implements Identity.Groups.
func (id *identity) Groups() ([]string, error) {
	if id.client.permChecker != nil {
		return id.client.permChecker.cache.Groups(id.username)
	}
	return nil, nil
}

// Allow implements Identity.Allow.
func (id *identity) Allow(ctx context.Context, acl []string) (bool, error) {
	if id.client.permChecker != nil {
		return id.client.permChecker.Allow(id.username, acl)
	}
	// No groups - just implement the trivial cases.
	ok, _ := trivialAllow(id.username, acl)
	return ok, nil
}

// Id implements Identity.Id.
func (id *identity) Id() string {
	return id.username
}

// Domain implements Identity.Domain.
func (id *identity) Domain() string {
	return ""
}
