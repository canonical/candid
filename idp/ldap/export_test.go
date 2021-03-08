// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package ldap

import (
	"gopkg.in/canonical/candid.v2/idp"
)

type LDAPConn ldapConn
type LDAPDialer func(network, address string) (LDAPConn, error)

func SetLDAP(p idp.IdentityProvider, dialer LDAPDialer) {
	p.(*identityProvider).dialLDAP = func(netw, addr string) (ldapConn, error) {
		return dialer(netw, addr)
	}
}
