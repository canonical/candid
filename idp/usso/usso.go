// Copyright 2015 Canonical Ltd.

// Pacakge usso is an identity provider that authenticates against Ubuntu
// SSO using OpenID.
package usso

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/juju/loggo"
	"github.com/juju/names"
	openid "github.com/yohcop/openid-go"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
	"github.com/CanonicalLtd/blues-identity/store"
)

var logger = loggo.GetLogger("identity.idp.usso")

func init() {
	config.RegisterIDP("usso", func(func(interface{}) error) (idp.IdentityProvider, error) {
		return IdentityProvider, nil
	})
}

// IdentityProvider is an idp.IdentityProvider that provides
// authentication via Ubuntu SSO.
var IdentityProvider idp.IdentityProvider = &identityProvider{
	nonceStore:     openid.NewSimpleNonceStore(),
	discoveryCache: openid.NewSimpleDiscoveryCache(),
}

const (
	ussoURL = "https://login.ubuntu.com"
)

// TODO It should not be necessary to know all the possible
// groups in advance.
//
// This list needs to contain any private teams that the system needs to know about.
const openIdRequestedTeams = "blues-development,charm-beta"

// USSOIdentityProvider allows login using Ubuntu SSO credentials.
type identityProvider struct {
	// TODO (mhilton) provide a new mechanism for this.
	// noncePool      *mgononcestore.Pool
	nonceStore     openid.NonceStore
	discoveryCache *openid.SimpleDiscoveryCache
	initParams     idp.InitParams
}

// Name gives the name of the identity provider (usso).
func (*identityProvider) Name() string {
	return "usso"
}

// Domain implements idp.IdentityProvider.Domain.
func (*identityProvider) Domain() string {
	return ""
}

// Description gives a description of the identity provider.
func (*identityProvider) Description() string {
	return "Ubuntu SSO"
}

// Interactive specifies that this identity provider is interactive.
func (*identityProvider) Interactive() bool {
	return true
}

// Init initialises this identity provider
func (idp *identityProvider) Init(_ context.Context, params idp.InitParams) error {
	idp.initParams = params
	return nil
}

// URL gets the login URL to use this identity provider.
func (idp *identityProvider) URL(waitID string) string {
	return idputil.URL(idp.initParams.URLPrefix, "/login", waitID)
}

// Handle handles the Ubuntu SSO login process.
func (idp *identityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	logger.Debugf("handling %s", req.URL.Path)
	switch req.URL.Path {
	case "/callback":
		if err := idp.callback(ctx, w, req); err != nil {
			idp.initParams.LoginCompleter.Failure(ctx, w, req, idputil.WaitID(req), err)
		}
	default:
		if err := idp.login(ctx, w, req); err != nil {
			idp.initParams.LoginCompleter.Failure(ctx, w, req, idputil.WaitID(req), err)
		}
	}
}

func (idp *identityProvider) login(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	realm := idp.initParams.URLPrefix + "/callback"
	callback := realm
	if waitid := idputil.WaitID(req); waitid != "" {
		callback += "?waitid=" + waitid
	}
	u, err := openid.RedirectURL(ussoURL, callback, realm)
	if err != nil {
		return errgo.Mask(err)
	}
	ext := url.Values{}
	ext.Set("openid.ns.sreg", "http://openid.net/extensions/sreg/1.1")
	ext.Set("openid.sreg.required", "email,fullname,nickname")
	ext.Set("openid.ns.lp", "http://ns.launchpad.net/2007/openid-teams")
	ext.Set("openid.lp.query_membership", openIdRequestedTeams)
	http.Redirect(w, req, fmt.Sprintf("%s&%s", u, ext.Encode()), http.StatusFound)
	return nil
}

// ussoCallbackRequest documents the /v1/idp/usso/callback endpoint. This
// is used by the UbuntuSSO login sequence to indicate it has completed.
// Client code should not need to use this type.
type callbackRequest struct {
	OPEndpoint string `httprequest:"openid.op_endpoint,form"`
	ExternalID string `httprequest:"openid.claimed_id,form"`
	Signed     string `httprequest:"openid.signed,form"`
	Email      string `httprequest:"openid.sreg.email,form"`
	Fullname   string `httprequest:"openid.sreg.fullname,form"`
	Nickname   string `httprequest:"openid.sreg.nickname,form"`
	Groups     string `httprequest:"openid.lp.is_member,form"`
}

func (idp *identityProvider) callback(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	var r callbackRequest
	if err := httprequest.Unmarshal(idputil.RequestParams(ctx, w, req), &r); err != nil {
		return errgo.Mask(err)
	}
	u, err := url.Parse(idp.initParams.URLPrefix + req.URL.String())
	if err != nil {
		return errgo.Mask(err)
	}
	// openid.Verify gets the endpoint name from openid.endpoint, but
	// the spec says it's openid.op_endpoint. Munge it in to make
	// openid.Verify happy.
	q := u.Query()
	if q.Get("openid.endpoint") == "" {
		q.Set("openid.endpoint", q.Get("openid.op_endpoint"))
	}
	u.RawQuery = q.Encode()
	id, err := openid.Verify(
		u.String(),
		idp.discoveryCache,
		idp.nonceStore,
	)
	if err != nil {
		return errgo.Mask(err)
	}
	if r.OPEndpoint != ussoURL+"/+openid" {
		return errgo.WithCausef(nil, params.ErrForbidden, "rejecting login from %s", r.OPEndpoint)
	}
	user, err := userFromCallback(&r)
	// If userFromCallback returns an error it is because the
	// OpenID simple registration fields (see
	// http://openid.net/specs/openid-simple-registration-extension-1_1-01.html)
	// were not filled out in the callback. This means that a new
	// identity cannot be created. It is still possible to log the
	// user in if the identity already exists.
	if err != nil {
		identity := store.Identity{
			ProviderID: store.MakeProviderIdentity("usso", id),
		}
		serr := idp.initParams.Store.Identity(ctx, &identity)
		if serr == nil {
			idp.initParams.LoginCompleter.Success(ctx, w, req, idputil.WaitID(req), &identity)
			return nil
		}
		if errgo.Cause(serr) != store.ErrNotFound {
			return errgo.Mask(serr)
		}
		return errgo.WithCausef(err, params.ErrForbidden, "invalid user")
	}

	if err := idp.initParams.Store.UpdateIdentity(ctx, user, store.Update{
		store.Username: store.Set,
		store.Name:     store.Set,
		store.Email:    store.Set,
		store.Groups:   store.Push,
	}); err != nil {
		return errgo.Mask(err)
	}
	idp.initParams.LoginCompleter.Success(ctx, w, req, idputil.WaitID(req), user)
	return nil
}

// userFromCallback creates a new user document from the callback
// parameters.
func userFromCallback(r *callbackRequest) (*store.Identity, error) {
	signed := make(map[string]bool)
	for _, f := range strings.Split(r.Signed, ",") {
		signed[f] = true
	}
	if r.Nickname == "" || !signed["sreg.nickname"] {
		return nil, errgo.New("username not specified")
	}
	if !names.IsValidUser(r.Nickname) {
		return nil, errgo.Newf("invalid username %q", r.Nickname)
	}
	if r.Email == "" || !signed["sreg.email"] {
		return nil, errgo.New("email address not specified")
	}
	if r.Fullname == "" || !signed["sreg.fullname"] {
		return nil, errgo.New("full name not specified")
	}

	var groups []string
	if r.Groups != "" && signed["lp.is_member"] {
		groups = strings.Split(r.Groups, ",")
	}
	return &store.Identity{
		ProviderID: store.MakeProviderIdentity("usso", r.ExternalID),
		Username:   r.Nickname,
		Email:      r.Email,
		Name:       r.Fullname,
		Groups:     groups,
	}, nil
}
