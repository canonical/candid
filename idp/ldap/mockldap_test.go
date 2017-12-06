// Copyright 2018 Canonical Ltd.

package ldap_test

import (
	"crypto/tls"
	"fmt"

	idpldap "github.com/CanonicalLtd/blues-identity/idp/ldap"
	"gopkg.in/asn1-ber.v1"
	"gopkg.in/ldap.v2"
)

type mockLDAPDialer struct {
	db    ldapDB
	conns []*mockLDAPConn
}

func newMockLDAPDialer(db ldapDB) *mockLDAPDialer {
	d := &mockLDAPDialer{db: db}
	d.conns = []*mockLDAPConn{}
	return d
}

func (d *mockLDAPDialer) Dial(network, address string) (idpldap.LDAPConn, error) {
	conn := &mockLDAPConn{network: network, address: address, db: d.db}
	d.conns = append(d.conns, conn)
	return conn, nil
}

type mockLDAPConn struct {
	db ldapDB
	// network and address are set to the arguments passed to the dial
	// function.
	network string
	address string

	// tlsConfig is set when StartTLS is called.
	tlsConfig *tls.Config
	// searchReq is set when Search is called.
	searchReq *ldap.SearchRequest
	// boundUsername and boundPassword are set when Bind is called.
	boundUsername string
	boundPassword string
	// closed is set when Close is called.
	closed bool
}

func (c *mockLDAPConn) StartTLS(config *tls.Config) error {
	c.tlsConfig = config
	return nil
}

func (c *mockLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	c.searchReq = req

	found, err := c.db.Search(req.Filter)
	if err != nil {
		return nil, err
	}

	entries := make([]*ldap.Entry, len(found))
	for i, res := range found {
		attrs := []*ldap.EntryAttribute{}
		for _, name := range req.Attributes {
			values, ok := res[name]
			if !ok {
				continue
			}
			attrs = append(
				attrs, &ldap.EntryAttribute{
					Name:   name,
					Values: values,
				})
		}
		entries[i] = &ldap.Entry{
			DN:         res["dn"][0],
			Attributes: attrs,
		}
	}
	return &ldap.SearchResult{Entries: entries}, nil
}

func (c *mockLDAPConn) Bind(username, password string) error {
	for _, entry := range c.db {
		dn, ok := entry["dn"]
		if !ok || len(dn) == 0 || dn[0] != username {
			continue
		}

		userPassword, ok := entry["userPassword"]
		if !ok || len(userPassword) == 0 {
			continue
		}
		if userPassword[0] == password {
			c.boundUsername = username
			c.boundPassword = password
			return nil
		}
	}
	return fmt.Errorf("Login failure")
}

func (c *mockLDAPConn) Close() {
	c.closed = true
}

type ldapDoc map[string][]string
type ldapDB []ldapDoc

func (db ldapDB) Search(filter string) ([]ldapDoc, error) {
	match, err := filterMatcher(filter)
	if err != nil {
		return nil, err
	}

	var found []ldapDoc
	for _, doc := range db {
		if match(doc) {
			found = append(found, doc)
		}
	}
	return found, nil
}

// filterMatcher returns a function that reports whether a given LDAP document
// matches the LDAP filter. It returns an error if the filter is malformed.
func filterMatcher(filter string) (func(ldapDoc) bool, error) {
	packet, err := ldap.CompileFilter(filter)
	if err != nil {
		return nil, err
	}
	return packetFilterMatcher(packet), nil
}

func packetFilterMatcher(packet *ber.Packet) func(ldapDoc) bool {
	switch packet.Tag {
	case ldap.FilterAnd:
		var children []func(ldapDoc) bool
		for _, child := range packet.Children {
			children = append(children, packetFilterMatcher(child))
		}
		return func(doc ldapDoc) bool {
			for _, child := range children {
				if !child(doc) {
					return false
				}
			}
			return true
		}
	case ldap.FilterOr:
		var children []func(ldapDoc) bool
		for _, child := range packet.Children {
			children = append(children, packetFilterMatcher(child))
		}
		return func(doc ldapDoc) bool {
			for _, child := range children {
				if child(doc) {
					return true
				}
			}
			return true
		}
	case ldap.FilterNot:
		child := packetFilterMatcher(packet.Children[0])
		return func(doc ldapDoc) bool {
			return !child(doc)
		}

	case ldap.FilterEqualityMatch:
		expected := string(packet.Children[1].Data.Bytes())
		return func(doc ldapDoc) bool {
			values, ok := doc[string(packet.Children[0].Data.Bytes())]
			if !ok {
				return false
			}
			for _, value := range values {
				if value == expected {
					return true
				}
			}
			return false
		}

	default:
		panic(fmt.Sprintf("unimplemented tag: %v", packet.Tag))
	}
}
