// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package ldap contains identity providers that validate against ldap
// servers.
package ldap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/ldap.v2"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"gopkg.in/canonical/candid.v2/idp"
	"gopkg.in/canonical/candid.v2/idp/idputil"
	"gopkg.in/canonical/candid.v2/params"
	"gopkg.in/canonical/candid.v2/store"
)

var logger = loggo.GetLogger("candid.idp.ldap")

func init() {
	idp.Register("ldap", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
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

	// Icon contains the URL or path of an icon.
	Icon string `yaml:"icon"`

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

	// Hidden is set if the IDP should be hidden from interactive
	// prompts.
	Hidden bool `yaml:"hidden"`
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
	if p.Icon == "" {
		p.Icon = "/static/images/icons/ldap.svg"
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

// IconURL returns the URL of an icon for the identity provider.
func (idp *identityProvider) IconURL() string {
	return idputil.ServiceURL(idp.initParams.Location, idp.params.Icon)
}

// Interactive implements idp.IdentityProvider.Interactive.
func (*identityProvider) Interactive() bool {
	return true
}

// Hidden implements idp.IdentityProvider.Hidden.
func (idp *identityProvider) Hidden() bool {
	return idp.params.Hidden
}

// Init implements idp.IdentityProvider.Init.
func (idp *identityProvider) Init(ctx context.Context, params idp.InitParams) error {
	idp.initParams = params
	return nil
}

// URL implements idp.IdentityProvider.URL.
func (idp *identityProvider) URL(state string) string {
	return idputil.RedirectURL(idp.initParams.URLPrefix, "/login", state)
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

	logger.Tracef("LDAP groups search: basedn=%s scope=sub deref_aliases=never filter=%s attributes=[\"cn\"]", idp.baseDN, filter)
	req := &ldap.SearchRequest{
		BaseDN:       idp.baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   []string{"cn"},
	}
	res, err := conn.Search(req)
	if err != nil {
		logger.Tracef("LDAP search error: %s", err)
		return nil, errgo.Mask(err)
	}
	logResults(res)

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
	var ls idputil.LoginState
	if err := idp.initParams.Codec.Cookie(req, idputil.LoginCookieName, req.Form.Get("state"), &ls); err != nil {
		logger.Infof("Invalid login state: %s", err)
		idputil.BadRequestf(w, "Login failed: invalid login state")
		return
	}
	switch strings.TrimPrefix(req.URL.Path, idp.initParams.URLPrefix) {
	case "/login":
		idpChoice := params.IDPChoiceDetails{
			Domain:      idp.params.Domain,
			Description: idp.params.Description,
			Name:        idp.params.Name,
			URL:         idp.URL(req.Form.Get("state")),
		}
		id, err := idputil.HandleLoginForm(ctx, w, req, idpChoice, idp.initParams.Template, idp.loginUser)
		if err != nil {
			idp.initParams.VisitCompleter.RedirectFailure(ctx, w, req, ls.ReturnTo, ls.State, err)
		}
		if id != nil {
			idp.initParams.VisitCompleter.RedirectSuccess(ctx, w, req, ls.ReturnTo, ls.State, id)
		}
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
	id, err := idp.loginDN(ctx, conn, dn, password)
	if err != nil {
		if errgo.Cause(err) == params.ErrNotFound {
			return nil, errgo.Notef(err, "user %q not found", username)
		}
		return nil, errgo.Mask(err)
	}
	return id, nil
}

func (idp *identityProvider) loginDN(ctx context.Context, conn ldapConn, dn, password string) (*store.Identity, error) {
	logger.Tracef("LDAP bind: dn=%s", dn)
	if err := conn.Bind(dn, password); err != nil {
		logger.Tracef("LDAP bind error: %s", err)
		// Assume all bind errors represent invalid credentials,
		// other errors will have most likely been picked up
		// resolving the username.
		return nil, errgo.New("invalid username or password")
	}
	logger.Tracef("LDAP bind success")

	logger.Tracef("LDAP user search: basedn=%s scope=base deref_aliases=never filter=%s attributes=%s", dn, idp.params.UserQueryFilter, idp.userQueryAttrs)
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
		logger.Tracef("LDAP search error: %s", err)
		return nil, errgo.Mask(err)
	}
	logResults(res)
	if len(res.Entries) == 0 {
		return nil, errgo.WithCausef(nil, params.ErrNotFound, "")
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
	filter := fmt.Sprintf("(%s=%s)", idp.params.UserQueryAttrs.ID, ldap.EscapeFilter(username))
	logger.Tracef("LDAP user search: basedn=%s scope=sub deref_aliases=never filter=%s", idp.baseDN, filter)
	req := &ldap.SearchRequest{
		BaseDN:       idp.baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    1,
		Filter:       filter,
	}
	res, err := conn.Search(req)
	if err != nil {
		logger.Tracef("LDAP search error: %s", err)
		return "", errgo.Mask(err)
	}
	logResults(res)
	if len(res.Entries) < 1 {
		return "", errgo.New("invalid username or password")
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
		logger.Tracef("LDAP bind: dn=%s", idp.params.DN)
		if err := conn.Bind(idp.params.DN, idp.params.Password); err != nil {
			logger.Tracef("LDAP bind error: %s", err)
			return nil, errgo.Mask(err)
		}
		logger.Tracef("LDAP bind success", err)
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

func logResults(res *ldap.SearchResult) {
	if logger.EffectiveLogLevel() > loggo.TRACE {
		return
	}
	logger.Tracef("LDAP search results:")
	for _, e := range res.Entries {
		logger.Tracef("\tDN=%s", e.DN)
		logger.Tracef("\tAttributes:")
		for _, a := range e.Attributes {
			logger.Tracef("\t\t%s=%s", a.Name, strings.Join(a.Values, ","))
		}
	}
}
