// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Pacakge usso is an identity provider that authenticates against Ubuntu
// SSO using OpenID.
package usso

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/juju/loggo"
	"github.com/juju/names/v4"
	"github.com/juju/usso"
	"github.com/juju/usso/openid"
	"github.com/juju/utils/cache"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"launchpad.net/lpad"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/idputil"
	"github.com/canonical/candid/idp/usso/internal/kvnoncestore"
	"github.com/canonical/candid/params"
	"github.com/canonical/candid/store"
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
	// Name is the name that will be given to the identity provider.
	Name string `yaml:"name"`

	// Description is the description that will be used with the
	// identity provider. If this is not set then Name will be used.
	Description string `yaml:"description"`

	// LaunchpadTeams contains any private teams that the system needs to
	// know about.
	LaunchpadTeams []string `yaml:"launchpad-teams"`

	// Domain contains the domain that the identities are created in.
	Domain string

	// Icon contains the URL or path of an icon.
	Icon string `yaml:"icon"`

	// Staging enables using the staging login and launchpad servers.
	Staging bool

	// FixedUsername stops any username changes in Ubuntu SSO being
	// propergated into candid. Once an identity has been registered it's
	// Username will not be changed.
	FixedUsername bool `yaml:"fixed-username"`
}

// NewIdentityProvider creates a new LDAP identity provider.
func NewIdentityProvider(p Params) idp.IdentityProvider {
	if p.Name == "" {
		p.Name = "usso"
	}
	if p.Description == "" {
		p.Description = "Ubuntu SSO"
	}
	if p.Icon == "" {
		p.Icon = "/static/images/icons/usso.svg"
	}
	return &identityProvider{
		groupCache: cache.New(10 * time.Minute),
		groupMonitor: prometheus.NewSummary(prometheus.SummaryOpts{
			Namespace: "candid",
			Subsystem: "launchpad",
			Name:      "get_launchpad_groups",
			Help:      "The duration of launchpad login, /people, and super_teams_collection_link requests.",
		}),
		params: p,
	}
}

// USSOIdentityProvider allows login using Ubuntu SSO credentials.
type identityProvider struct {
	client       *openid.Client
	initParams   idp.InitParams
	groupCache   *cache.Cache
	groupMonitor prometheus.Summary
	params       Params
}

// Name gives the name of the identity provider (usso).
func (idp *identityProvider) Name() string {
	return idp.params.Name
}

// Domain implements idp.IdentityProvider.Domain.
func (idp *identityProvider) Domain() string {
	return idp.params.Domain
}

// Description gives a description of the identity provider.
func (idp *identityProvider) Description() string {
	return idp.params.Description
}

// IconURL returns the URL of an icon for the identity provider.
func (idp *identityProvider) IconURL() string {
	return idputil.ServiceURL(idp.initParams.Location, idp.params.Icon)
}

// Interactive specifies that this identity provider is interactive.
func (*identityProvider) Interactive() bool {
	return true
}

// Hidden implements idp.IdentityProvider.Hidden.
func (*identityProvider) Hidden() bool {
	return false
}

// Init initialises this identity provider
func (idp *identityProvider) Init(_ context.Context, params idp.InitParams) error {
	idp.initParams = params
	srv := usso.ProductionUbuntuSSOServer
	if idp.params.Staging {
		srv = usso.StagingUbuntuSSOServer
	}
	idp.client = openid.NewClient(
		srv,
		kvnoncestore.New(params.KeyValueStore, time.Minute),
		nil,
	)
	return nil
}

// URL gets the login URL to use this identity provider.
func (idp *identityProvider) URL(state string) string {
	return idputil.RedirectURL(idp.initParams.URLPrefix, "/login", state)
}

// SetInteraction sets the interaction information for
func (idp *identityProvider) SetInteraction(ierr *httpbakery.Error, dischargeID string) {
}

// Handle handles the Ubuntu SSO login process.
func (idp *identityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/callback":
		idp.callback(ctx, w, req)
	default:
		idp.login(ctx, w, req)
	}
}

func (idp *identityProvider) login(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	query := "?state=" + idputil.State(req)
	realm := idp.initParams.URLPrefix + "/callback"
	callback := realm + query
	url := idp.client.RedirectURL(&openid.Request{
		ReturnTo:     callback,
		Realm:        realm,
		Teams:        idp.params.LaunchpadTeams,
		SRegRequired: []string{openid.SRegEmail, openid.SRegFullName, openid.SRegNickname},
	})
	http.Redirect(w, req, url, http.StatusFound)
}

func (idp *identityProvider) callback(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	var ls idputil.LoginState
	if err := idp.initParams.Codec.Cookie(req, idputil.LoginCookieName, req.Form.Get("state"), &ls); err != nil {
		logger.Infof("Invalid login state: %s", err)
		idputil.BadRequestf(w, "Login failed: invalid login state")
		return
	}

	successf := func(id *store.Identity) {
		idp.initParams.VisitCompleter.RedirectSuccess(ctx, w, req, ls.ReturnTo, ls.State, id)
	}
	errorf := func(err error) {
		idp.initParams.VisitCompleter.RedirectFailure(ctx, w, req, ls.ReturnTo, ls.State, err)
	}

	resp, err := idp.client.Verify(idp.initParams.URLPrefix + req.URL.String())
	if err != nil {
		errorf(err)
		return
	}

	// Work around bug in the usso package
	if len(resp.Teams) == 1 && resp.Teams[0] == "" {
		resp.Teams = nil
	}

	var username string
	if resp.SReg[openid.SRegNickname] != "" {
		username = idputil.NameWithDomain(resp.SReg[openid.SRegNickname], idp.params.Domain)
	}
	email := resp.SReg[openid.SRegEmail]
	fullname := resp.SReg[openid.SRegFullName]
	var providerInfo map[string][]string
	if len(resp.Teams) > 0 {
		providerInfo = map[string][]string{
			"groups": resp.Teams,
		}
	}

	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity(idp.Name(), resp.ID),
	}
	err = idp.initParams.Store.Identity(ctx, &identity)
	if errgo.Cause(err) == store.ErrNotFound {
		// If the identity is not found this is the first time they have
		// logged in, attempt to create an identity for them.
		identity.Username = username
		identity.Email = email
		identity.Name = fullname
		identity.ProviderInfo = providerInfo
		err = idp.registerIdentity(ctx, &identity)
		if errgo.Cause(err) == store.ErrDuplicateUsername {
			// TODO(mhilton) format an error with useful instructions.
			logger.Errorf("Error creating identity for %s, duplicate username %s", identity.ProviderID, username)
			err = errgo.WithCausef(nil, params.ErrorCode("bad username"), "cannot create identity with username %s", username)
		}
	}
	if err != nil {
		errorf(err)
		return
	}

	var doUpdate bool
	var update store.Update
	updateIdentity := identity
	if !idp.params.FixedUsername && username != "" && username != identity.Username {
		// TODO(mhilton): candid should have a service wide policy for
		// username validity.
		if names.IsValidUser(username) {
			doUpdate = true
			updateIdentity.Username = username
			update[store.Username] = store.Set
		} else {
			logger.Warningf("not updating username for %s to invalid username %q", identity.ProviderID, username)
		}
	}
	if email != "" && email != identity.Email {
		doUpdate = true
		updateIdentity.Email = email
		update[store.Email] = store.Set
	}
	if fullname != "" && fullname != identity.Name {
		doUpdate = true
		updateIdentity.Name = fullname
		update[store.Name] = store.Set
	}
	if len(providerInfo) != 0 && !valuesMatch(providerInfo["groups"], identity.ProviderInfo["groups"]) {
		doUpdate = true
		updateIdentity.ProviderInfo = providerInfo
		update[store.ProviderInfo] = store.Set
	}

	if doUpdate {
		if err := idp.initParams.Store.UpdateIdentity(ctx, &updateIdentity, update); err != nil {
			// If the identity information cannot be updated, just stick
			// with the old data. We know who the identity is.
			logger.Errorf("cannot update indentity information for %s: %v", updateIdentity.ProviderID, err)
		} else {
			identity = updateIdentity
		}
	}

	successf(&identity)
}

func (idp *identityProvider) registerIdentity(ctx context.Context, identity *store.Identity) error {
	switch {
	case identity.Username == "":
		return errgo.New("username not specified")
	case !names.IsValidUser(identity.Username):
		return errgo.WithCausef(nil, params.ErrorCode("bad username"), "invalid username %q", identity.Username)
	case identity.Email == "":
		return errgo.New("email address not specified")
	case identity.Name == "":
		return errgo.New("full name not specified")
	}
	err := idp.initParams.Store.UpdateIdentity(ctx, identity, store.Update{
		store.Username:     store.Set,
		store.Email:        store.Set,
		store.Name:         store.Set,
		store.ProviderInfo: store.Set,
	})
	return errgo.Mask(err, errgo.Is(store.ErrDuplicateUsername))
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
	privateGroups := id.ProviderInfo["groups"]
	allGroups := make([]string, len(groups)+len(privateGroups))
	copy(allGroups, groups)
	copy(allGroups[len(groups):], privateGroups)
	return allGroups, nil
}

// getLaunchpadGroups tries to fetch the list of teams the user
// belongs to in launchpad. Only public teams are supported.
func (idp *identityProvider) getLaunchpadGroupsNoCache(ussoID string) ([]string, error) {
	srv := lpad.Production
	if idp.params.Staging {
		srv = lpad.Staging
	}
	root, err := lpad.Login(srv, &lpad.OAuth{Consumer: "idm", Anonymous: true})
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
	lpPrefix := "https://login.launchpad.net/+id/"
	ussoPrefix := "https://login.ubuntu.com/+id/"
	if idp.params.Staging {
		lpPrefix = "https://login-lp.staging.ubuntu.com/+id/"
		ussoPrefix = "https://login.staging.ubuntu.com/+id/"
	}

	launchpadID := lpPrefix + strings.TrimPrefix(ussoID, ussoPrefix)
	v, err := root.Location("/people").Get(lpad.Params{"ws.op": "getByOpenIDIdentifier", "identifier": launchpadID})
	// TODO if err == lpad.ErrNotFound, return a not found error
	// so that we won't round-trip to launchpad for users that don't exist there.
	if err != nil {
		return nil, errgo.Notef(err, "cannot find user %s", ussoID)
	}
	return &lpad.Person{v}, nil
}

// valuesMatch determines if string sets a and b contain exactly the same
// values.
func valuesMatch(a, b []string) bool {
	// filter out any repeated values in a
	inA := make(map[string]bool, len(a))
	for _, v := range a {
		inA[v] = true
	}
	inB := make(map[string]bool, len(b))
	for _, v := range b {
		inB[v] = true
	}
	if len(inA) != len(inB) {
		return false
	}
	for k := range inA {
		if !inB[k] {
			return false
		}
	}
	return true
}
