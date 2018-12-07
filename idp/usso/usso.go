// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Pacakge usso is an identity provider that authenticates against Ubuntu
// SSO using OpenID.
package usso

import (
	"net/http"
	"strings"
	"time"

	"github.com/juju/loggo"
	"github.com/juju/names"
	"github.com/juju/usso"
	"github.com/juju/usso/openid"
	"github.com/juju/utils/cache"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idputil"
	"github.com/CanonicalLtd/candid/idp/idputil/secret"
	"github.com/CanonicalLtd/candid/idp/usso/internal/kvnoncestore"
	"github.com/CanonicalLtd/candid/store"
)

var logger = loggo.GetLogger("candid.idp.usso")

func init() {
	idp.Register("usso", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
		var p Params
		if err := unmarshal(&p); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal usso parameters")
		}
		return NewIdentityProvider(p), nil
	})
}

type Params struct {
	// LaunchpadTeams contains any private teams that the system needs to know about.
	LaunchpadTeams []string `yaml:"launchpad-teams"`

	// Domain contains the domain that the identities are created in.
	Domain string
}

// NewIdentityProvider creates a new LDAP identity provider.
func NewIdentityProvider(p Params) idp.IdentityProvider {
	return &identityProvider{
		groupCache: cache.New(10 * time.Minute),
		groupMonitor: prometheus.NewSummary(prometheus.SummaryOpts{
			Namespace: "candid",
			Subsystem: "launchpad",
			Name:      "get_launchpad_groups",
			Help:      "The duration of launchpad login, /people, and super_teams_collection_link requests.",
		}),
		launchpadTeams: p.LaunchpadTeams,
		domain:         p.Domain,
	}
}

// USSOIdentityProvider allows login using Ubuntu SSO credentials.
type identityProvider struct {
	client       *openid.Client
	initParams   idp.InitParams
	codec        *secret.Codec
	groupCache   *cache.Cache
	groupMonitor prometheus.Summary
	// launchpadTeams contains any private teams that the system needs to know about.
	launchpadTeams []string
	domain         string
}

// Name gives the name of the identity provider (usso).
func (*identityProvider) Name() string {
	return "usso"
}

// Domain implements idp.IdentityProvider.Domain.
func (idp *identityProvider) Domain() string {
	return idp.domain
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
	idp.client = openid.NewClient(
		usso.ProductionUbuntuSSOServer,
		kvnoncestore.New(params.KeyValueStore, time.Minute),
		nil,
	)
	idp.codec = secret.NewCodec(params.Key)
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
		idp.callback(ctx, w, req)
	default:
		idp.login(ctx, w, req)
	}
}

func (idp *identityProvider) login(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	query := ""
	if returnTo, state := idputil.RedirectParams(req); returnTo != "" {
		verification, err := idp.codec.SetCookie(w, idputil.RedirectCookieName, idputil.RedirectState{
			ReturnTo: returnTo,
			State:    state,
		})
		if err != nil {
			idp.initParams.VisitCompleter.RedirectFailure(ctx, w, req, returnTo, state, errgo.Mask(err))
			return
		}
		query = "?state=" + verification
	} else if dischargeID := idputil.DischargeID(req); dischargeID != "" {
		query = "?id=" + dischargeID
	}
	realm := idp.initParams.URLPrefix + "/callback"
	callback := realm + query
	url := idp.client.RedirectURL(&openid.Request{
		ReturnTo:     callback,
		Realm:        realm,
		Teams:        idp.launchpadTeams,
		SRegRequired: []string{openid.SRegEmail, openid.SRegFullName, openid.SRegNickname},
	})
	http.Redirect(w, req, url, http.StatusFound)
}

func (idp *identityProvider) callback(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	successf := func(id *store.Identity) {
		idp.initParams.VisitCompleter.Success(ctx, w, req, idputil.DischargeID(req), id)
	}
	errorf := func(err error) {
		idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
	}
	if verification := req.Form.Get("state"); verification != "" {
		var rs idputil.RedirectState
		if err := idp.codec.Cookie(req, idputil.RedirectCookieName, verification, &rs); err != nil {
			errorf(err)
			return
		}
		successf = func(id *store.Identity) {
			idp.initParams.VisitCompleter.RedirectSuccess(ctx, w, req, rs.ReturnTo, rs.State, id)
		}
		errorf = func(err error) {
			idp.initParams.VisitCompleter.RedirectFailure(ctx, w, req, rs.ReturnTo, rs.State, err)
		}
	}

	resp, err := idp.client.Verify(idp.initParams.URLPrefix + req.URL.String())
	if err != nil {
		errorf(err)
		return
	}

	username := resp.SReg[openid.SRegNickname]
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("usso", resp.ID),
		Username:   idputil.NameWithDomain(username, idp.domain),
		Email:      resp.SReg[openid.SRegEmail],
		Name:       resp.SReg[openid.SRegFullName],
		ProviderInfo: map[string][]string{
			"groups": resp.Teams,
		},
	}
	switch {
	case username == "":
		err = errgo.New("username not specified")
	case !names.IsValidUser(username):
		err = errgo.Newf("invalid username %q", username)
	case identity.Email == "":
		err = errgo.New("email address not specified")
	case identity.Name == "":
		err = errgo.New("full name not specified")
	}
	// If we have an error it is because
	// the OpenID simple registration fields (see
	// http://openid.net/specs/openid-simple-registration-extension-1_1-01.html)
	// were not filled out in the callback. This means that a new
	// identity cannot be created. It is still possible to log the
	// user in if the identity already exists.
	if err != nil {
		serr := idp.initParams.Store.Identity(ctx, &identity)
		if serr == nil {
			successf(&identity)
			return
		}
		if errgo.Cause(serr) == store.ErrNotFound {
			serr = errgo.WithCausef(err, params.ErrForbidden, "invalid user")
		}
		errorf(serr)
		return
	}

	if err := idp.initParams.Store.UpdateIdentity(ctx, &identity, store.Update{
		store.Username:     store.Set,
		store.Name:         store.Set,
		store.Email:        store.Set,
		store.ProviderInfo: store.Set,
	}); err != nil {
		errorf(err)
		return
	}
	successf(&identity)
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
