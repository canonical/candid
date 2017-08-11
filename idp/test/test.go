// Copyright 2015 Canonical Ltd.

// Package test contains an identity provider useful for testing other
// parts of the system. The test identity provider is insecure by design
// so should not be used in any production system.
package test

import (
	"net/http"
	"net/url"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
	"github.com/CanonicalLtd/blues-identity/store"
)

func init() {
	config.RegisterIDP("test", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
		var p Params
		if err := unmarshal(&p); err != nil {
			return nil, errgo.Mask(err)
		}
		if p.Name == "" {
			p.Name = "test"
		}
		return NewIdentityProvider(p), nil
	})
}

type Params struct {
	// Name is the name that will be used with the identity provider.
	Name string

	// Domain contains the domain that will be used with the identity
	// provider.
	Domain string
}

// NewIdentityProvider creates an idp.IdentityProvider that can be used
// for tests.
func NewIdentityProvider(p Params) idp.IdentityProvider {
	return &identityProvider{
		params: p,
	}
}

type identityProvider struct {
	params     Params
	initParams idp.InitParams
}

// Name implements idp.IdentityProvider.Name.
func (idp *identityProvider) Name() string {
	return idp.params.Name
}

// Domain implements idp.IdentityProvider.Domain.
func (idp *identityProvider) Domain() string {
	return idp.params.Domain
}

// Description gives a description of the identity provider.
func (*identityProvider) Description() string {
	return "Test"
}

// Interactive specifies that this identity provider is interactive.
func (*identityProvider) Interactive() bool {
	return true
}

// Init implements idp.IdentityProvider.Init.
func (idp *identityProvider) Init(ctx context.Context, params idp.InitParams) error {
	idp.initParams = params
	return nil
}

// URL gets the login URL to use this identity provider.
func (idp *identityProvider) URL(waitID string) string {
	return idputil.URL(idp.initParams.URLPrefix, "/test-login", waitID)
}

type testInteractiveLoginResponse struct {
	URL string `json:"url"`
}

type testLoginRequest struct {
	httprequest.Route `httprequest:"POST"`
	User              *params.User `httprequest:",body"`
}

// Handle handles the login process.
func (idp *identityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	id, err := idp.handle(ctx, w, req)
	if err != nil {
		idp.initParams.LoginCompleter.Failure(ctx, w, req, idputil.WaitID(req), err)
	} else if id != nil {
		idp.initParams.LoginCompleter.Success(ctx, w, req, idputil.WaitID(req), id)
	}
}

func (idp *identityProvider) handle(ctx context.Context, w http.ResponseWriter, req *http.Request) (*store.Identity, error) {
	switch req.Method {
	case "GET":
		httprequest.WriteJSON(w, http.StatusOK, testInteractiveLoginResponse{
			URL: idp.URL(idputil.WaitID(req)),
		})
	case "POST":
		return idp.handlePost(ctx, w, req)
	default:
		return nil, errgo.WithCausef(nil, params.ErrMethodNotAllowed, "%s not allowed", req.Method)
	}
	return nil, nil
}

func (idp *identityProvider) handlePost(ctx context.Context, w http.ResponseWriter, req *http.Request) (*store.Identity, error) {
	var lr testLoginRequest
	if err := httprequest.Unmarshal(idputil.RequestParams(ctx, w, req), &lr); err != nil {
		return nil, err
	}
	if lr.User.ExternalID != "" && lr.User.Username != "" {
		if err := idp.updateUser(ctx, lr.User); err != nil {
			return nil, errgo.Mask(err, errgo.Is(params.ErrAlreadyExists))
		}
	}
	id := store.Identity{
		ProviderID: store.ProviderIdentity(lr.User.ExternalID),
		Username:   string(lr.User.Username),
	}
	if err := idp.initParams.Store.Identity(ctx, &id); err != nil {
		if errgo.Cause(err) == store.ErrNotFound {
			return nil, errgo.WithCausef(err, params.ErrNotFound, "")
		}
		return nil, errgo.Mask(err)
	}
	return &id, nil
}

func (idp *identityProvider) updateUser(ctx context.Context, u *params.User) error {
	id := store.Identity{
		ProviderID: store.ProviderIdentity(u.ExternalID),
		Username:   string(u.Username),
		Name:       u.FullName,
		Email:      u.Email,
		Groups:     u.IDPGroups,
	}
	update := store.Update{
		store.Username: store.Set,
	}
	if id.Name != "" {
		update[store.Name] = store.Set
	}
	if id.Email != "" {
		update[store.Email] = store.Set
	}
	if len(id.Groups) > 0 {
		update[store.Groups] = store.Set
	}
	if err := idp.initParams.Store.UpdateIdentity(ctx, &id, update); err != nil {
		if errgo.Cause(err) == store.ErrDuplicateUsername {
			return errgo.WithCausef(err, params.ErrAlreadyExists, "")
		}
		return errgo.Mask(err)
	}
	return nil
}

var _ httpbakery.Visitor = Visitor{}

type Visitor struct {
	// User contains the user to log in as. User may be fully defined
	// in which case the user is added to the database or can be a
	// Username or ExternalID. If the latter two cases the database
	// will be checked for a matching user.
	User *params.User
}

func (v Visitor) VisitWebPage(ctx context.Context, client *httpbakery.Client, urls map[string]*url.URL) error {
	cl := &httprequest.Client{
		Doer: client,
	}
	if u, ok := urls["test"]; ok {
		return v.nonInteractive(ctx, cl, u)
	}
	return v.interactive(ctx, cl, urls[httpbakery.UserInteractionMethod])
}

// Interactive is a web page visit function that performs an interactive
// login.
func (v Visitor) interactive(ctx context.Context, client *httprequest.Client, u *url.URL) error {
	var resp testInteractiveLoginResponse
	if err := client.Get(ctx, u.String(), &resp); err != nil {
		return errgo.Mask(err)
	}
	if err := v.doLogin(ctx, client, resp.URL); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// NonInteractive is a web page visit function that performs an
// non-interactive login.
func (v Visitor) nonInteractive(ctx context.Context, client *httprequest.Client, u *url.URL) error {
	if err := v.doLogin(ctx, client, u.String()); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// doLogin performs the common part of the login.
func (v Visitor) doLogin(ctx context.Context, client *httprequest.Client, url string) error {
	req := &testLoginRequest{
		User: v.User,
	}
	if err := client.CallURL(ctx, url, req, nil); err != nil {
		return errgo.Mask(err)
	}
	return nil
}
