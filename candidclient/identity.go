// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package candidclient

import (
	"context"

	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"

	"github.com/canonical/candid/params"
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

var _ Identity = (*usernameIdentity)(nil)

type usernameIdentity struct {
	client   *Client
	username string
}

// Username implements Identity.Username.
func (id *usernameIdentity) Username() (string, error) {
	return id.username, nil
}

// Groups implements Identity.Groups.
func (id *usernameIdentity) Groups() ([]string, error) {
	if id.client.permChecker != nil {
		return id.client.permChecker.cache.Groups(id.username)
	}
	return nil, nil
}

// Allow implements Identity.Allow.
func (id *usernameIdentity) Allow(ctx context.Context, acl []string) (bool, error) {
	if id.client.permChecker != nil {
		return id.client.permChecker.Allow(id.username, acl)
	}
	// No groups - just implement the trivial cases.
	ok, _ := trivialAllow(id.username, acl)
	return ok, nil
}

// Id implements Identity.Id.
func (id *usernameIdentity) Id() string {
	return id.username
}

// Domain implements Identity.Domain.
func (id *usernameIdentity) Domain() string {
	return ""
}

type useridIdentity struct {
	client *Client
	user   params.User
}

// Username implements Identity.Username.
func (id *useridIdentity) Username() (string, error) {
	if id.user.Username != "" {
		return string(id.user.Username), nil
	}

	ctx := context.Background()
	user, err := id.client.GetUserWithID(ctx, &params.GetUserWithIDRequest{
		UserID: id.user.ExternalID,
	})
	if err != nil {
		return "", errgo.Mask(err)
	}
	id.user = *user
	return string(id.user.Username), nil
}

// Groups implements Identity.Groups.
func (id *useridIdentity) Groups() ([]string, error) {
	_, err := id.Username()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return id.user.IDPGroups, nil
}

// Allow implements Identity.Allow.
func (id *useridIdentity) Allow(ctx context.Context, acl []string) (bool, error) {
	groups, err := id.Groups()
	if err != nil {
		return false, errgo.Mask(err)
	}

	groups = append(groups, string(id.user.Username))
	for _, g := range groups {
		if ok, _ := trivialAllow(g, acl); ok {
			return true, nil
		}
	}
	return false, nil
}

// Id implements Identity.Id.
func (id *useridIdentity) Id() string {
	return id.user.ExternalID
}

// Domain implements Identity.Domain.
func (id *useridIdentity) Domain() string {
	return ""
}
