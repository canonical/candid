// Copyright 2017 Canonical Ltd.

// Package ldap contains identity providers that validate against ldap
// servers.
package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	ldap "gopkg.in/ldap.v2"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

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
}

// NewIdentityProvider creates a new LDAP identity provider.
func NewIdentityProvider(p Params) (idp.IdentityProvider, error) {
	if p.Description == "" {
		p.Description = p.Name
	}

	idp := &identityProvider{
		params: p,
	}

	u, err := url.Parse(p.URL)
	if err != nil {
		return nil, errgo.Notef(err, "cannot parse URL")
	}
	switch u.Scheme {
	case "ldap":
		idp.network = "tcp"
		port := u.Port()
		if port == "" {
			port = "ldap"
		}
		host := u.Hostname()
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

	network   string
	address   string
	baseDN    string
	tlsConfig tls.Config
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
func (idp *identityProvider) GetGroups(context.Context, *store.Identity) ([]string, error) {
	// TODO (mhilton) get groups.
	return nil, nil
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
		return errgo.WithCausef(nil, params.ErrBadRequest, "unsuppoered method %q", req.Method)
	case "GET":
		return errgo.Mask(idp.initParams.Template.ExecuteTemplate(w, "login-form", nil))
	case "POST":
		id, err := idp.loginUID(ctx, req.Form.Get("username"), req.Form.Get("password"))
		if err != nil {
			return err
		}
		idp.initParams.VisitCompleter.Success(ctx, w, req, idputil.DischargeID(req), id)
		return nil
	}
}

func (idp *identityProvider) loginUID(ctx context.Context, uid, password string) (*store.Identity, error) {
	conn, err := idp.dial()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer conn.Close()
	req := &ldap.SearchRequest{
		BaseDN:       idp.baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    1,
		Filter:       fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(uid)),
		Attributes:   []string{"dn"},
	}
	res, err := conn.Search(req)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if len(res.Entries) < 1 {
		return nil, errgo.Newf("user %s not found", uid)
	}
	return idp.loginDN(ctx, conn, res.Entries[0].DN, password)
}

func (idp *identityProvider) loginDN(ctx context.Context, conn *ldap.Conn, dn, password string) (*store.Identity, error) {
	if err := conn.Bind(dn, password); err != nil {
		return nil, errgo.Mask(err)
	}
	req := &ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    1,
		Filter:       "(objectClass=*)", // (objectClass=*) matches everything.
		Attributes:   []string{"uid", "displayName", "mail"},
	}
	res, err := conn.Search(req)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	var username, email, name string
	for _, attr := range res.Entries[0].Attributes {
		switch attr.Name {
		case "uid":
			username = idputil.NameWithDomain(attr.Values[0], idp.params.Domain)
		case "mail":
			email = attr.Values[0]
		case "displayName":
			name = attr.Values[0]
		}
	}
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

// dial establishes a connection to the LDAP server and binds as the
// search user (if specified).
func (idp *identityProvider) dial() (*ldap.Conn, error) {
	conn, err := ldap.Dial(idp.network, idp.address)
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
