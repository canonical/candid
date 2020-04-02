// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package candidclient

import (
	"context"
	"strings"

	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
)

// StripDomain returns an implementation of identchecker.IdentityClient
// that strips the given
// domain name off any user and group names returned from it. It also
// adds it as an @ suffix when querying for ACL membership for names
// that don't already contain a domain.
//
// This is useful when an existing user of the identity manager needs to
// obtain backwardly compatible usernames when an identity manager is
// changed to add a domain suffix.
func StripDomain(candidClient *Client, domain string) identchecker.IdentityClient {
	return &domainStrippingClient{
		domain: "@" + domain,
		c:      candidClient,
	}
}

// domainStrippingClient implements IdentityClient by stripping a given
// domain off any declared users.
type domainStrippingClient struct {
	domain string
	c      *Client
}

// DeclaredIdentity implements IdentityClient.DeclaredIdentity.
func (c *domainStrippingClient) DeclaredIdentity(ctx context.Context, attrs map[string]string) (identchecker.Identity, error) {
	ident0, err := c.c.DeclaredIdentity(ctx, attrs)
	if err != nil {
		return nil, err
	}
	return &domainStrippingIdentity{
		Identity: ident0.(Identity),
		domain:   c.domain,
	}, nil
}

// DeclaredIdentity implements IdentityClient.IdentityCaveats.
func (c *domainStrippingClient) IdentityFromContext(ctx context.Context) (identchecker.Identity, []checkers.Caveat, error) {
	return c.c.IdentityFromContext(ctx)
}

var _ Identity = (*domainStrippingIdentity)(nil)

type domainStrippingIdentity struct {
	domain string
	Identity
}

// Username implements ACLUser.IdentityCaveats.
func (u *domainStrippingIdentity) Username() (string, error) {
	name, err := u.Identity.Username()
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(name, u.domain), nil
}

// Groups implements ACLUser.Groups.
func (u *domainStrippingIdentity) Groups() ([]string, error) {
	groups, err := u.Identity.Groups()
	if err != nil {
		return nil, err
	}
	for i, g := range groups {
		groups[i] = strings.TrimSuffix(g, u.domain)
	}
	return groups, nil
}

// Allow implements ACLUser.Allow by adding stripped
// domain to all names in acl that don't have a domain
// before calling the underlying Allow method.
func (u *domainStrippingIdentity) Allow(ctx context.Context, acl []string) (bool, error) {
	acl1 := make([]string, len(acl))
	for i, name := range acl {
		if !strings.Contains(name, "@") {
			acl1[i] = name + u.domain
		} else {
			acl1[i] = name
		}
	}
	ok, err := u.Identity.Allow(ctx, acl1)
	if err != nil {
		return false, errgo.Mask(err)
	}
	if ok {
		return true, nil
	}
	// We were denied access with the suffix added, but perhaps
	// the identity manager isn't yet adding suffixes - we still
	// want it to work in that case, so try without the added
	// suffixes.
	ok, err = u.Identity.Allow(ctx, acl)
	if err != nil {
		return false, errgo.Mask(err)
	}
	return ok, nil
}
