// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package ldap contains identity providers that validate against ldap
// servers.
package ldap

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/idmclient.v1/params"
	"gopkg.in/ldap.v2"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
	"github.com/CanonicalLtd/blues-identity/store"
)

func init() {
	config.RegisterIDP("ldap", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
		var p Params
		if err := unmarshal(&p); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal ldap parameters")
		}
		if p.Name == "" {
			return nil, errgo.Newf("name not specified")
		}

		idp, err := NewIdentityProvider(p)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		return idp, nil
	})
}

type Params struct {
	// Name is the name that will be given to the identity provider.
	Name string `yaml:"name"`

	// Description is the description that will be used with the
	// identity provider. If this is not set then Name will be used.
	Description string `yaml:"description"`

	// Domain is the domain with which all identities created by this
	// identity provider will be tagged (not including the @ separator).
	Domain string `yaml:"domain"`

	// URL contains an LDAP URL indicating the server to connect to.
	URL string `yaml:"url"`

	// CACertificate contains a PEM encoded CA certificate to verify
	// the ldap connection against.
	CACertificate string `yaml:"ca-cert"`

	// DN contains the distinguished name that is used to bind to the
	// LDAP server to perform searches. If this is empty then the IDP
	// will bind anonymously and Password will be ignored.
	DN string `yaml:"dn"`

	// Password contains the password to use to when binding to the
	// LDAP server as DN.
	Password string `yaml:"password"`

	// UserQueryFilter defines the filter for searching users.
	UserQueryFilter string `yaml:"user-query-filter"`

	// UserQueryAttrs defines how user attributes are mapped to attributes in
	// the LDAP entry.
	UserQueryAttrs UserQueryAttrs `yaml:"user-query-attrs"`

	// GroupQueryFilter defines the template for the LDAP filter to search for
	// the groups that a user belongs to. The .User value is defined to hold
	// the user id being searched for - e.g.
	//    (&(objectClass=groupOfNames)(member={{.User}}))
	GroupQueryFilter string `yaml:"group-query-filter"`
}

// UserQueryAttrs defines how user attributes are mapped to attributes in the
// LDAP entry.
type UserQueryAttrs struct {
	// ID defines the attribute used to identify a user.
	ID string `yaml:"id"`

	// UserQueryEmailAttr defines the attribute for a user e-mail.
	Email string `yaml:"email"`

	// UserQueryDisplayNameAttr defines the attribute for a user display name.
	// If not specified, "displayName" is used.
	DisplayName string `yaml:"display-name"`
}

type groupQueryArg struct {
	User string
}

// NewIdentityProvider creates a new LDAP identity provider.
func NewIdentityProvider(p Params) (idp.IdentityProvider, error) {
	if p.Description == "" {
		p.Description = p.Name
	}

	if p.UserQueryAttrs.ID == "" {
		return nil, errgo.Newf("missing 'id' config parameter in 'user-query-attrs'")
	}
	userQueryAttrs := []string{p.UserQueryAttrs.ID}
	if p.UserQueryAttrs.Email != "" {
		userQueryAttrs = append(userQueryAttrs, p.UserQueryAttrs.Email)
	}
	if p.UserQueryAttrs.DisplayName != "" {
		userQueryAttrs = append(userQueryAttrs, p.UserQueryAttrs.DisplayName)
	}

	if p.UserQueryFilter == "" {
		return nil, errgo.Newf("missing 'user-query-filter' config parameter")
	}
	if p.GroupQueryFilter == "" {
		return nil, errgo.Newf("missing 'group-query-filter' config parameter")
	}

	groupQueryFilterTemplate, err := template.New(
		"group-query-filter").Parse(p.GroupQueryFilter)
	if err != nil {
		return nil, errgo.Notef(err, "invalid 'group-query-filter' config parameter")
	}
	testFilter, err := renderTemplate(groupQueryFilterTemplate, groupQueryArg{User: "sample"})
	if err != nil {
		return nil, errgo.Notef(err, "invalid 'group-query-filter' config parameter")
	}
	if _, err = ldap.CompileFilter(testFilter); err != nil {
		return nil, errgo.Notef(err, "invalid 'group-query-filter' config parameter")
	}

	idp := &identityProvider{
		params:                   p,
		dialLDAP:                 dialLDAP,
		userQueryAttrs:           userQueryAttrs,
		groupQueryFilterTemplate: groupQueryFilterTemplate,
	}

	u, err := url.Parse(p.URL)
	if err != nil {
		return nil, errgo.Notef(err, "cannot parse URL")
	}
	switch u.Scheme {
	case "ldap":
		idp.network = "tcp"
		// It would be nice to use u.Host and u.Port here, but
		// these aren't available in go 1.6.
		host, port, _ := net.SplitHostPort(u.Host)
		if host == "" {
			// Asume that the URL didn't specify a port.
			host = u.Host
			port = "ldap"
		}
		idp.address = net.JoinHostPort(host, port)
		idp.tlsConfig.ServerName = host
	default:
		// No other schemes are currently supported.
		return nil, errgo.Newf("unsupported scheme %q", u.Scheme)
	}
	idp.baseDN = strings.TrimPrefix(u.Path, "/")
	if p.CACertificate != "" {
		idp.tlsConfig.RootCAs = x509.NewCertPool()
		idp.tlsConfig.RootCAs.AppendCertsFromPEM([]byte(p.CACertificate))
	}
	return idp, nil
}

type identityProvider struct {
	params     Params
	initParams idp.InitParams

	dialLDAP  func(network, addr string) (ldapConn, error)
	network   string
	address   string
	baseDN    string
	tlsConfig tls.Config

	userQueryAttrs           []string
	groupQueryFilterTemplate *template.Template
}

// Name implements idp.IdentityProvider.Name.
func (idp *identityProvider) Name() string {
	return idp.params.Name
}

// Domain implements idp.IdentityProvider.Domain.
func (idp *identityProvider) Domain() string {
	return idp.params.Domain
}

// Description implements idp.IdentityProvider.Description.
func (idp *identityProvider) Description() string {
	return idp.params.Description
}

// Interactive implements idp.IdentityProvider.Interactive.
func (*identityProvider) Interactive() bool {
	return true
}

// Init implements idp.IdentityProvider.Init.
func (idp *identityProvider) Init(ctx context.Context, params idp.InitParams) error {
	idp.initParams = params
	return nil
}

// URL implements idp.IdentityProvider.URL.
func (idp *identityProvider) URL(dischargeID string) string {
	return idputil.URL(idp.initParams.URLPrefix, "/login", dischargeID)
}

// URL implements idp.IdentityProvider.SetInteraction.
func (idp *identityProvider) SetInteraction(ierr *httpbakery.Error, dischargeID string) {
}

//  GetGroups implements idp.IdentityProvider.GetGroups.
func (idp *identityProvider) GetGroups(ctx context.Context, identity *store.Identity) ([]string, error) {
	conn, err := idp.dial()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer conn.Close()

	_, uid := identity.ProviderID.Split()
	filter, err := renderTemplate(
		idp.groupQueryFilterTemplate, groupQueryArg{User: ldap.EscapeFilter(uid)})
	if err != nil {
		return nil, errgo.Mask(err)
	}

	req := &ldap.SearchRequest{
		BaseDN:       idp.baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   []string{"cn"},
	}
	res, err := conn.Search(req)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	groups := []string{}
	for _, entry := range res.Entries {
		if entry == nil || len(entry.Attributes) == 0 || len(entry.Attributes[0].Values) == 0 {
			continue
		}
		groups = append(groups, entry.Attributes[0].Values[0])
	}
	return groups, nil
}

// Handle implements idp.IdentityProvider.Handle.
func (idp *identityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	switch strings.TrimPrefix(req.URL.Path, idp.initParams.URLPrefix) {
	case "/login":
		if err := idp.handleLogin(ctx, w, req); err != nil {
			idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
		}
	}
}

func (idp *identityProvider) handleLogin(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	switch req.Method {
	default:
		return errgo.WithCausef(nil, params.ErrBadRequest, "unsupported method %q", req.Method)
	case "GET":
		return errgo.Mask(idp.initParams.Template.ExecuteTemplate(w, "login-form", nil))
	case "POST":
		id, err := idp.loginUser(ctx, req.Form.Get("username"), req.Form.Get("password"))
		if err != nil {
			return err
		}
		idp.initParams.VisitCompleter.Success(ctx, w, req, idputil.DischargeID(req), id)
		return nil
	}
}

func (idp *identityProvider) loginUser(ctx context.Context, username, password string) (*store.Identity, error) {
	conn, err := idp.dial()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer conn.Close()

	dn, err := idp.resolveUsername(conn, username)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return idp.loginDN(ctx, conn, dn, password)
}

func (idp *identityProvider) loginDN(ctx context.Context, conn ldapConn, dn, password string) (*store.Identity, error) {
	if err := conn.Bind(dn, password); err != nil {
		return nil, errgo.Mask(err)
	}
	req := &ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    1,
		Filter:       idp.params.UserQueryFilter,
		Attributes:   idp.userQueryAttrs,
	}
	res, err := conn.Search(req)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	var username, email, name string
	for _, attr := range res.Entries[0].Attributes {
		switch attr.Name {
		case idp.params.UserQueryAttrs.ID:
			username = idputil.NameWithDomain(attr.Values[0], idp.params.Domain)
		case idp.params.UserQueryAttrs.Email:
			email = attr.Values[0]
		case idp.params.UserQueryAttrs.DisplayName:
			name = attr.Values[0]
		}
	}
	// set groups
	id := &store.Identity{
		ProviderID: store.MakeProviderIdentity(idp.params.Name, dn),
		Username:   username,
		Name:       name,
		Email:      email,
	}
	err = idp.initParams.Store.UpdateIdentity(ctx, id, store.Update{
		store.Username: store.Set,
		store.Name:     store.Set,
		store.Email:    store.Set,
	})
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return id, nil
}

// resolveUsername returns the DN for a username
func (idp *identityProvider) resolveUsername(conn ldapConn, username string) (string, error) {
	req := &ldap.SearchRequest{
		BaseDN:       idp.baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    1,
		Filter: fmt.Sprintf(
			"(%s=%s)", idp.params.UserQueryAttrs.ID, ldap.EscapeFilter(username)),
	}
	res, err := conn.Search(req)
	if err != nil {
		return "", errgo.Mask(err)
	}
	if len(res.Entries) < 1 {
		return "", errgo.Newf("user %q not found", username)
	}
	return res.Entries[0].DN, nil
}

// dial establishes a connection to the LDAP server and binds as the
// search user (if specified).
func (idp *identityProvider) dial() (ldapConn, error) {
	conn, err := idp.dialLDAP(idp.network, idp.address)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if err = conn.StartTLS(&idp.tlsConfig); err != nil {
		return nil, errgo.Mask(err)
	}
	if idp.params.DN != "" {
		if err := conn.Bind(idp.params.DN, idp.params.Password); err != nil {
			return nil, errgo.Mask(err)
		}
	}
	return conn, nil
}

func renderTemplate(tmpl *template.Template, ctx interface{}) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func dialLDAP(network, addr string) (ldapConn, error) {
	c, err := ldap.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ldapConn represents the subset of ldap connection methods used
// by the provider. It is defined so that it can be replaced for testing.
type ldapConn interface {
	StartTLS(config *tls.Config) error
	Bind(username, password string) error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close()
}
