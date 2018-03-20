// Copyright 2015 Canonical Ltd.

// Pacakge usso is an identity provider that authenticates against Ubuntu
// SSO using OpenID.
package usso

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juju/loggo"
	"github.com/juju/names"
	"github.com/juju/utils/cache"
	"github.com/prometheus/client_golang/prometheus"
	openid "github.com/yohcop/openid-go"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/juju/idmclient.v1/params"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/kvnoncestore"
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
	discoveryCache: openid.NewSimpleDiscoveryCache(),
	groupCache:     cache.New(10 * time.Minute),
	groupMonitor: prometheus.NewSummary(prometheus.SummaryOpts{
		Namespace: "blues_identity",
		Subsystem: "launchpad",
		Name:      "get_launchpad_groups",
		Help:      "The duration of launchpad login, /people, and super_teams_collection_link requests.",
	}),
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
	nonceStore     openid.NonceStore
	discoveryCache *openid.SimpleDiscoveryCache
	initParams     idp.InitParams
	groupCache     *cache.Cache
	groupMonitor   prometheus.Summary
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
	idp.nonceStore = kvnoncestore.New(params.KeyValueStore, time.Minute)
	return nil
}

// URL gets the login URL to use this identity provider.
func (idp *identityProvider) URL(dischargeID string) string {
	return idputil.URL(idp.initParams.URLPrefix, "/login", dischargeID)
}

// SetInteraction sets the interaction information for
func (idp *identityProvider) SetInteraction(ierr *httpbakery.Error, dischargeID string) {
}

// Handle handles the Ubuntu SSO login process.
func (idp *identityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	logger.Debugf("handling %s", req.URL.Path)
	switch req.URL.Path {
	case "/callback":
		if err := idp.callback(ctx, w, req); err != nil {
			idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
		}
	default:
		if err := idp.login(ctx, w, req); err != nil {
			idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
		}
	}
}

func (idp *identityProvider) login(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	realm := idp.initParams.URLPrefix + "/callback"
	callback := realm
	if dischargeID := idputil.DischargeID(req); dischargeID != "" {
		callback += "?id=" + dischargeID
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
			idp.initParams.VisitCompleter.Success(ctx, w, req, idputil.DischargeID(req), &identity)
			return nil
		}
		if errgo.Cause(serr) != store.ErrNotFound {
			return errgo.Mask(serr)
		}
		return errgo.WithCausef(err, params.ErrForbidden, "invalid user")
	}

	if err := idp.initParams.Store.UpdateIdentity(ctx, user, store.Update{
		store.Username:     store.Set,
		store.Name:         store.Set,
		store.Email:        store.Set,
		store.ProviderInfo: store.Set,
	}); err != nil {
		return errgo.Mask(err)
	}
	idp.initParams.VisitCompleter.Success(ctx, w, req, idputil.DischargeID(req), user)
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
		ProviderInfo: map[string][]string{
			"groups": groups,
		},
	}, nil
}

// GetGroups implements idp.IdentityProvider.GetGroups by fetching group
// information from launchpad.
func (idp *identityProvider) GetGroups(_ context.Context, id *store.Identity) ([]string, error) {
	_, ussoID := id.ProviderID.Split()
	groups0, err := idp.groupCache.Get(ussoID, func() (interface{}, error) {
		t := time.Now()
		groups, err := idp.getLaunchpadGroupsNoCache(ussoID)
		idp.groupMonitor.Observe(float64(time.Since(t)) / float64(time.Microsecond))
		return groups, err
	})
	if err != nil {
		return nil, errgo.Mask(err)
	}
	groups := groups0.([]string)
	if len(groups) == 0 {
		return id.ProviderInfo["groups"], nil
	}
	privateGroups := id.ProviderInfo["groups"]
	if len(privateGroups) == 0 {
		return groups, nil
	}
	allGroups := make([]string, len(groups)+len(privateGroups))
	copy(allGroups, groups)
	copy(allGroups[len(groups):], privateGroups)
	return allGroups, nil
}

// getLaunchpadGroups tries to fetch the list of teams the user
// belongs to in launchpad. Only public teams are supported.
func (idp *identityProvider) getLaunchpadGroupsNoCache(ussoID string) ([]string, error) {
	root, err := lpad.Login(lpad.Production, &lpad.OAuth{Consumer: "idm", Anonymous: true})
	if err != nil {
		return nil, errgo.Notef(err, "cannot connect to launchpad")
	}
	user, err := idp.getLaunchpadPersonByOpenID(root, ussoID)
	if err != nil {
		return nil, errgo.Notef(err, "cannot find user %s", ussoID)
	}
	teams, err := user.Link("super_teams_collection_link").Get(nil)
	if err != nil {
		return nil, errgo.Notef(err, "cannot get team list for launchpad user %q", user.Name())
	}
	groups := make([]string, 0, teams.TotalSize())
	teams.For(func(team *lpad.Value) error {
		groups = append(groups, team.StringField("name"))
		return nil
	})
	return groups, nil
}

func (idp *identityProvider) getLaunchpadPersonByOpenID(root *lpad.Root, ussoID string) (*lpad.Person, error) {
	launchpadID := "https://login.launchpad.net/+id/" + strings.TrimPrefix(ussoID, "https://login.ubuntu.com/+id/")
	v, err := root.Location("/people").Get(lpad.Params{"ws.op": "getByOpenIDIdentifier", "identifier": launchpadID})
	// TODO if err == lpad.ErrNotFound, return a not found error
	// so that we won't round-trip to launchpad for users that don't exist there.
	if err != nil {
		return nil, errgo.Notef(err, "cannot find user %s", ussoID)
	}
	return &lpad.Person{v}, nil
}
