// Copyright 2018 Canonical Ltd.

package ldap

import (
	"github.com/CanonicalLtd/blues-identity/idp"
)

type LDAPConn ldapConn
type LDAPDialer func(network, address string) (LDAPConn, error)

func SetLDAP(p idp.IdentityProvider, dialer LDAPDialer) {
	p.(*identityProvider).dialLDAP = func(netw, addr string) (ldapConn, error) {
		return dialer(netw, addr)
	}
}
