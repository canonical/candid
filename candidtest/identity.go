// Copyright 2017 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package candidtest

import (
	"context"

	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v3/bakery/checkers"
	"gopkg.in/macaroon-bakery.v3/bakery/identchecker"

	"github.com/canonical/candid/candidclient"
)

// identityClient implement identchecker.IdentityClient. This is used because
// the candidtest server cannot use candidclient.Client because that uses the
// groups endpoint, which cannot be used because that would lead to an
// infinite recursion.
type identityClient struct {
	srv *Server
}

func (i identityClient) IdentityFromContext(ctx context.Context) (identchecker.Identity, []checkers.Caveat, error) {
	return nil, candidclient.IdentityCaveats(i.srv.URL.String()), nil
}

func (i identityClient) DeclaredIdentity(ctx context.Context, declared map[string]string) (identchecker.Identity, error) {
	username := declared["username"]
	if username == "" {
		return nil, errgo.Newf("no declared user name in %q", declared)
	}
	return &identity{
		srv: i.srv,
		id:  username,
	}, nil
}

type identity struct {
	srv *Server
	id  string
}

func (i identity) Id() string {
	return i.id
}

func (i identity) Domain() string {
	return ""
}

// Allow implements identchecker.ACLIdentity.Allow.
func (i identity) Allow(_ context.Context, acl []string) (bool, error) {
	groups := []string{i.id}
	u := i.srv.users[i.id]
	if u != nil {
		groups = append(groups, u.groups...)
	}
	for _, g1 := range groups {
		for _, g2 := range acl {
			if g1 == g2 {
				return true, nil
			}
		}
	}
	return false, nil
}
