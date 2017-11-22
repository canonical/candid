// Copyright 2015 Canonical Ltd.

// Package test contains an identity provider useful for testing other
// parts of the system. The test identity provider is insecure by design
// so should not be used in any production system.
package test

import (
	"net/http"
	"strings"

	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/juju/idmclient.v1/params"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

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

	// GetGroups contains function that if set will be called by
	// GetGroups to obtain the groups to return.
	GetGroups func(*store.Identity) ([]string, error)
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
func (idp *identityProvider) URL(dischargeID string) string {
	return idputil.URL(idp.initParams.URLPrefix, "/login", dischargeID)
}

// SetInteraction sets the interaction information for this identity provider.
func (idp *identityProvider) SetInteraction(ierr *httpbakery.Error, dischargeID string) {
	ierr.SetInteraction(authType, authInfo{
		URL: idputil.URL(idp.initParams.URLPrefix, "/interact", dischargeID),
	})
}

//  GetGroups implements idp.IdentityProvider.GetGroups.
func (idp *identityProvider) GetGroups(_ context.Context, id *store.Identity) ([]string, error) {
	f := idp.params.GetGroups
	if f == nil {
		return nil, nil
	}
	return f(id)
}

// Handle handles the login process.
func (idp *identityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	id, err := idp.handle(ctx, w, req)
	if err != nil {
		idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
	} else if id != nil {
		idp.initParams.VisitCompleter.Success(ctx, w, req, idputil.DischargeID(req), id)
	}
}

type testInteractiveLoginResponse struct {
	URL string `json:"url"`
}

func (idp *identityProvider) handle(ctx context.Context, w http.ResponseWriter, req *http.Request) (*store.Identity, error) {
	switch req.Method {
	case "GET":
		httprequest.WriteJSON(w, http.StatusOK, testInteractiveLoginResponse{
			URL: idp.URL(idputil.DischargeID(req)),
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
	switch strings.TrimPrefix(req.URL.Path, idp.initParams.URLPrefix) {
	default:
		return nil, errgo.WithCausef(nil, params.ErrNotFound, "path %q not found", req.URL.Path)
	case "/interact":
		dt, err := idp.initParams.DischargeTokenCreator.DischargeToken(ctx, idputil.DischargeID(req), &id)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		httprequest.WriteJSON(w, http.StatusOK, testTokenResponse{
			DischargeToken: dt,
		})
		return nil, nil
	case "/login":
		return &id, nil
	}
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
