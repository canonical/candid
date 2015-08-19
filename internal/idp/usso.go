// Copyright 2015 Canonical Ltd.

package idp

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/juju/httprequest"
	"github.com/yohcop/openid-go"
	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

const (
	ussoURL = "https://login.ubuntu.com"
)

// TODO It should not be necessary to know all the possible
// groups in advance.
//
// This list needs to contain any private teams that the system needs to know about.
const openIdRequestedTeams = "blues-development,charm-beta"

// USSOIdentityProvider allows login using Ubuntu SSO credentials.
type USSOIdentityProvider struct {
	nonceStore     *openid.SimpleNonceStore
	discoveryCache *openid.SimpleDiscoveryCache
}

// NewUSSOIdentityProvider creates a new USSOIdentityProvider.
func NewUSSOIdentityProvider() *USSOIdentityProvider {
	return &USSOIdentityProvider{
		nonceStore: &openid.SimpleNonceStore{
			Store: make(map[string][]*openid.Nonce),
		},
		discoveryCache: &openid.SimpleDiscoveryCache{},
	}
}

// Name gives the name of the identity provider (usso).
func (*USSOIdentityProvider) Name() string {
	return "usso"
}

// Description gives a description of the identity provider.
func (*USSOIdentityProvider) Description() string {
	return "Ubuntu SSO"
}

// Interactive specifies that this identity provider is interactive.
func (*USSOIdentityProvider) Interactive() bool {
	return true
}

// URL gets the login URL to use this identity provider.
func (*USSOIdentityProvider) URL(c Context, waitID string) (string, error) {
	realm := c.IDPURL("/callback")
	callback := realm
	if waitID != "" {
		callback += "?waitid=" + waitID
	}
	u, err := openid.RedirectURL(ussoURL, callback, realm)
	if err != nil {
		return "", errgo.Mask(err)
	}
	ext := url.Values{}
	ext.Set("openid.ns.sreg", "http://openid.net/extensions/sreg/1.1")
	ext.Set("openid.sreg.required", "email,fullname,nickname")
	ext.Set("openid.ns.lp", "http://ns.launchpad.net/2007/openid-teams")
	ext.Set("openid.lp.query_membership", openIdRequestedTeams)
	return fmt.Sprintf("%s&%s", u, ext.Encode()), nil
}

// ussoCallbackRequest documents the /v1/idp/usso/callback endpoint. This
// is used by the UbuntuSSO login sequence to indicate it has completed.
// Client code should not need to use this type.
type ussoCallbackRequest struct {
	OPEndpoint string `httprequest:"openid.op_endpoint,form"`
	ExternalID string `httprequest:"openid.claimed_id,form"`
	Signed     string `httprequest:"openid.signed,form"`
	Email      string `httprequest:"openid.sreg.email,form"`
	Fullname   string `httprequest:"openid.sreg.fullname,form"`
	Nickname   string `httprequest:"openid.sreg.nickname,form"`
	Groups     string `httprequest:"openid.lp.is_member,form"`
}

// Handle handles the Ubuntu SSO login process.
func (u *USSOIdentityProvider) Handle(c Context) {
	var r ussoCallbackRequest
	if err := httprequest.Unmarshal(c.Params(), &r); err != nil {
		c.LoginFailure(err)
	}
	id, err := openid.Verify(
		c.RequestURL(),
		u.discoveryCache,
		u.nonceStore,
	)
	if err != nil {
		c.LoginFailure(err)
		return
	}
	if r.OPEndpoint != ussoURL+"/+openid" {
		c.LoginFailure(errgo.WithCausef(nil, params.ErrForbidden, "rejecting login from %s", r.OPEndpoint))
		return
	}
	identity, err := identityFromCallback(&r)
	// If identityFromCallback returns an error it is because the
	// OpenID simple registration fields (see
	// http://openid.net/specs/openid-simple-registration-extension-1_1-01.html)
	// were not filled out in the callback. This means that a new
	// identity cannot be created. It is still possible to log the
	// user in if the identity already exists.
	if err != nil {
		logger.Warningf("cannot create user: %s", err)
		var identity mongodoc.Identity
		if err := c.Store().DB.Identities().Find(bson.D{{"external_id", id}}).One(&identity); err != nil {
			c.LoginFailure(errgo.WithCausef(
				err,
				params.ErrForbidden,
				"cannot get user details for %q",
				id,
			))
			return
		}
		loginIdentity(c, &identity)
		return
	}
	err = c.Store().UpsertIdentity(identity)
	if err != nil {
		c.LoginFailure(err)
		return
	}
	loginIdentity(c, identity)
}

// identityFromCallback creates a new identity document from the callback
// parameters.
func identityFromCallback(r *ussoCallbackRequest) (*mongodoc.Identity, error) {
	signed := make(map[string]bool)
	for _, f := range strings.Split(r.Signed, ",") {
		signed[f] = true
	}
	if r.Email == "" || !signed["sreg.email"] {
		return nil, errgo.New("sreg.email not specified")
	}
	if r.Fullname == "" || !signed["sreg.fullname"] {
		return nil, errgo.New("sreg.fullname not specified")
	}
	if r.Nickname == "" || !signed["sreg.nickname"] {
		return nil, errgo.New("sreg.nickname not specified")
	}
	var groups []string
	if r.Groups != "" && signed["lp.is_member"] {
		groups = strings.Split(r.Groups, ",")
	}
	return &mongodoc.Identity{
		Username:   r.Nickname,
		ExternalID: r.ExternalID,
		Email:      r.Email,
		FullName:   r.Fullname,
		Groups:     groups,
	}, nil
}
