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
	"github.com/yohcop/openid-go"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/mgononcestore"
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
	noncePool:      mgononcestore.New(mgononcestore.Params{}),
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
	noncePool      *mgononcestore.Pool
	discoveryCache *openid.SimpleDiscoveryCache
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

// URL gets the login URL to use this identity provider.
func (*identityProvider) URL(c idp.Context, waitID string) string {
	return idputil.URL(c, "/login", waitID)
}

// Init initialises this identity provider
func (*identityProvider) Init(c idp.Context) error {
	return nil
}

// Handle handles the Ubuntu SSO login process.
func (idp *identityProvider) Handle(ctx idp.RequestContext, w http.ResponseWriter, req *http.Request) {
	logger.Debugf("handling %s", ctx.Path())
	switch ctx.Path() {
	case "/callback":
		idp.callback(ctx, w, req)
	default:
		idp.login(ctx, w, req)
	}
}

func (idp *identityProvider) login(ctx idp.RequestContext, w http.ResponseWriter, req *http.Request) {
	realm := ctx.URL("/callback")
	callback := realm
	if waitid := idputil.WaitID(req); waitid != "" {
		callback += "?waitid=" + waitid
	}
	u, err := openid.RedirectURL(ussoURL, callback, realm)
	if err != nil {
		ctx.LoginFailure(idputil.WaitID(req), err)
	}
	ext := url.Values{}
	ext.Set("openid.ns.sreg", "http://openid.net/extensions/sreg/1.1")
	ext.Set("openid.sreg.required", "email,fullname,nickname")
	ext.Set("openid.ns.lp", "http://ns.launchpad.net/2007/openid-teams")
	ext.Set("openid.lp.query_membership", openIdRequestedTeams)
	http.Redirect(w, req, fmt.Sprintf("%s&%s", u, ext.Encode()), http.StatusFound)
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

func (idp *identityProvider) callback(ctx idp.RequestContext, w http.ResponseWriter, req *http.Request) {
	var r callbackRequest
	if err := httprequest.Unmarshal(idputil.RequestParams(ctx, w, req), &r); err != nil {
		ctx.LoginFailure(idputil.WaitID(req), err)
		return
	}
	ns := idp.noncePool.Store(ctx.Database())
	defer ns.Close()
	u, err := url.Parse(ctx.RequestURL())
	if err != nil {
		ctx.LoginFailure(idputil.WaitID(req), err)
		return
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
		ns,
	)
	if err != nil {
		ctx.LoginFailure(idputil.WaitID(req), err)
		return
	}
	if r.OPEndpoint != ussoURL+"/+openid" {
		ctx.LoginFailure(idputil.WaitID(req), errgo.WithCausef(nil, params.ErrForbidden, "rejecting login from %s", r.OPEndpoint))
		return
	}
	user, err := userFromCallback(&r)
	// If userFromCallback returns an error it is because the
	// OpenID simple registration fields (see
	// http://openid.net/specs/openid-simple-registration-extension-1_1-01.html)
	// were not filled out in the callback. This means that a new
	// identity cannot be created. It is still possible to log the
	// user in if the identity already exists.
	if err != nil {
		if user, err := ctx.FindUserByExternalId(id); err == nil {
			idputil.LoginUser(ctx, idputil.WaitID(req), w, user)
			return
		}
		ctx.LoginFailure(idputil.WaitID(req), errgo.WithCausef(err, params.ErrForbidden, "invalid user"))
		return
	}
	err = ctx.UpdateUser(user)
	if err != nil {
		ctx.LoginFailure(idputil.WaitID(req), err)
		return
	}
	idputil.LoginUser(ctx, idputil.WaitID(req), w, user)
}

// userFromCallback creates a new user document from the callback
// parameters.
func userFromCallback(r *callbackRequest) (*params.User, error) {
	signed := make(map[string]bool)
	for _, f := range strings.Split(r.Signed, ",") {
		signed[f] = true
	}
	if r.Nickname == "" || !signed["sreg.nickname"] {
		return nil, errgo.New("username not specified")
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
	return &params.User{
		Username:   params.Username(r.Nickname),
		ExternalID: r.ExternalID,
		Email:      r.Email,
		FullName:   r.Fullname,
		IDPGroups:  groups,
	}, nil
}
