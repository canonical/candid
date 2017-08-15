// Copyright 2014 Canonical Ltd.

package auth

import (
	"bytes"
	"sort"
	"strings"

	"github.com/juju/idmclient/params"
	"github.com/juju/loggo"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	macaroon "gopkg.in/macaroon.v2-unstable"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/store"
)

var logger = loggo.GetLogger("identity.internal.auth")

const (
	AdminUsername     = "admin@idm"
	SSHKeyGetterGroup = "sshkeygetter@idm"
	GroupListGroup    = "grouplist@idm"
)

const (
	kindGlobal = "global"
	kindUser   = "u"
)

// Namespace contains the checkers.Namespace supported by the identity
// service.
var Namespace = checkers.NewNamespace(map[string]string{
	checkers.StdNamespace:        "",
	httpbakery.CheckersNamespace: "http",
	checkersNamespace:            "",
})

// The following constants define possible operation actions.
const (
	ActionRead               = "read"
	ActionVerify             = "verify"
	ActionDischargeFor       = "dischargeFor"
	ActionCreateAgent        = "createAgent"
	ActionReadAdmin          = "readAdmin"
	ActionWriteAdmin         = "writeAdmin"
	ActionReadGroups         = "readGroups"
	ActionWriteGroups        = "writeGroups"
	ActionReadSSHKeys        = "readSSHKeys"
	ActionWriteSSHKeys       = "writeSSHKeys"
	ActionLogin              = "login"
	ActionReadDischargeToken = "read-discharge-token"
)

// TODO(mhilton) make the admin ACL configurable
var AdminACL = []string{AdminUsername}

// An Authorizer is used to authorize operations in the identity server.
type Authorizer struct {
	adminUsername  string
	adminPassword  string
	location       string
	checker        *bakery.Checker
	store          store.Store
	groupResolvers map[string]groupResolver
}

// Params specifify the configuration parameters for a new Authroizer.
type Params struct {
	// AdminUsername is the username of the admin user in the
	// identity server.
	AdminUsername string

	// AdminPassword is the password of the admin user in the
	// identity server.
	AdminPassword string

	// Location is the url of the discharger that third-party caveats
	// will be addressed to. This should be the address of this
	// identity server.
	Location string

	// MacaroonOpStore is the store of macaroon operations and root
	// keys.
	MacaroonOpStore bakery.MacaroonOpStore

	// Store is the identity store.
	Store store.Store

	// IdentityProviders contains the set of identity providers that
	// are configured for the service. The authenticatore uses these
	// to get group information for authenticated users.
	IdentityProviders []idp.IdentityProvider
}

// New creates a new Authorizer for authorizing identity server
// operations.
func New(params Params) *Authorizer {
	a := &Authorizer{
		adminUsername: params.AdminUsername,
		adminPassword: params.AdminPassword,
		location:      params.Location,
		store:         params.Store,
	}
	resolvers := make(map[string]groupResolver)
	for _, idp := range params.IdentityProviders {
		idp := idp
		resolvers[idp.Name()] = idpGroupResolver{idp}
	}
	a.groupResolvers = resolvers
	a.checker = bakery.NewChecker(bakery.CheckerParams{
		Checker: newChecker(a),
		Authorizer: bakery.ACLAuthorizer{
			AllowPublic: true,
			GetACL: func(ctx context.Context, op bakery.Op) ([]string, error) {
				return a.aclForOp(ctx, op)
			},
		},
		IdentityClient:  identityClient{a},
		MacaroonOpStore: params.MacaroonOpStore,
	})
	return a
}

func (a *Authorizer) aclForOp(ctx context.Context, op bakery.Op) ([]string, error) {
	kind, name := splitEntity(op.Entity)
	switch kind {
	case kindGlobal:
		if name != "" {
			return nil, nil
		}
		switch op.Action {
		case ActionRead:
			// Only admins are allowed to read global information.
			return AdminACL, nil
		case ActionDischargeFor:
			// Only admins are allowed to discharge for other users.
			return AdminACL, nil
		case ActionVerify:
			// Everyone is allowed to verify a macaroon.
			return []string{bakery.Everyone}, nil
		case ActionLogin:
			// Everyone is allowed to log in.
			return []string{bakery.Everyone}, nil
		}
	case kindUser:
		if name == "" {
			return nil, nil
		}
		username := name
		acl := make([]string, 0, len(AdminACL)+2)
		acl = append(acl, AdminACL...)
		switch op.Action {
		case ActionRead:
			return append(acl, username), nil
		case ActionCreateAgent:
			return append(acl, "+create-agent@"+username), nil
		case ActionReadAdmin:
			return acl, nil
		case ActionWriteAdmin:
			return acl, nil
		case ActionReadGroups:
			// Administrators, users with GroupList permissions and the user
			// themselves can list their groups.
			return append(acl, username, GroupListGroup), nil
		case ActionWriteGroups:
			// Only administrators can set a user's groups.
			return acl, nil
		case ActionReadSSHKeys:
			return append(acl, username, SSHKeyGetterGroup), nil
		case ActionWriteSSHKeys:
			return append(acl, username), nil
		}
	}
	logger.Infof("no ACL found for op %#v", op)
	return nil, nil
}

// SetAdminPublicKey configures the public key on the admin user. This is
// to allow agent login as the admin user.
func (a *Authorizer) SetAdminPublicKey(ctx context.Context, pk *bakery.PublicKey) error {
	var pks []bakery.PublicKey
	if pk != nil {
		pks = append(pks, *pk)
	}
	return errgo.Mask(a.store.UpdateIdentity(
		ctx,
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("idm", "admin"),
			Username:   AdminUsername,
			Groups:     []string{AdminUsername},
			PublicKeys: pks,
		},
		store.Update{
			store.Username:   store.Set,
			store.Groups:     store.Set,
			store.PublicKeys: store.Set,
		},
	))
}

// Auth checks that client, as identified by the given context and
// macaroons, is authorized to perform the given operations. It may
// return an bakery.DischargeRequiredError when further checks are
// required, or params.ErrUnauthorized if the user is authenticated but
// does not have the required authorization.
func (a *Authorizer) Auth(ctx context.Context, mss []macaroon.Slice, ops ...bakery.Op) (*bakery.AuthInfo, error) {
	authInfo, err := a.checker.Auth(mss...).Allow(ctx, ops...)
	if err != nil {
		if errgo.Cause(err) == bakery.ErrPermissionDenied {
			return nil, errgo.WithCausef(err, params.ErrUnauthorized, "")
		}
		return nil, errgo.Mask(err, isDischargeRequiredError)
	}
	return authInfo, nil
}

func isDischargeRequiredError(err error) bool {
	_, ok := err.(*bakery.DischargeRequiredError)
	return ok
}

// Identity creates a new identity for the user with the given username,
// such a user must exist in the store.
func (a *Authorizer) Identity(ctx context.Context, username string) (*Identity, error) {
	id := &Identity{
		id: store.Identity{
			Username: username,
		},
		a: a,
	}
	if err := id.lookup(ctx); err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return id, nil
}

// UserHasPublicKeyCaveat creates a first-party caveat that ensures that
// the given user is associated with the given public key.
func UserHasPublicKeyCaveat(user params.Username, pk *bakery.PublicKey) checkers.Caveat {
	return checkers.Caveat{
		Namespace: checkersNamespace,
		Condition: checkers.Condition(userHasPublicKeyCondition, string(user)+" "+pk.String()),
	}
}

const checkersNamespace = "jujucharms.com/identity"
const userHasPublicKeyCondition = "user-has-public-key"

func newChecker(a *Authorizer) *checkers.Checker {
	checker := httpbakery.NewChecker()
	checker.Namespace().Register(checkersNamespace, "")
	checker.Register(userHasPublicKeyCondition, checkersNamespace, a.checkUserHasPublicKey)
	return checker
}

// checkUserHasPublicKey checks the "user-has-public-key" caveat.
func (a *Authorizer) checkUserHasPublicKey(ctx context.Context, cond, arg string) error {
	parts := strings.Fields(arg)
	if len(parts) != 2 {
		return errgo.New("caveat badly formatted")
	}
	var publicKey bakery.PublicKey
	if err := publicKey.UnmarshalText([]byte(parts[1])); err != nil {
		return errgo.Notef(err, "invalid public key %q", parts[1])
	}
	identity := store.Identity{
		Username: parts[0],
	}
	if err := a.store.Identity(ctx, &identity); err != nil {
		if errgo.Cause(err) != store.ErrNotFound {
			return errgo.Mask(err)
		}
		return errgo.Newf("public key not valid for user")
	}
	for _, pk := range identity.PublicKeys {
		if !bytes.Equal(pk.Key[:], publicKey.Key[:]) {
			continue
		}
		return nil
	}
	return errgo.Newf("public key not valid for user")
}

// An identityClient is an implementation of bakery.IdentityClient that
// uses the identity server's data store to get identity information.
type identityClient struct {
	a *Authorizer
}

// IdentityFromContext implements
// bakery.IdentityClient.IdentityFromContext by looking for admin
// credentials in the context.
func (c identityClient) IdentityFromContext(ctx context.Context) (_ident bakery.Identity, _ []checkers.Caveat, _ error) {
	logger.Debugf("identity from context %v {", ctx)
	defer func() {
		logger.Debugf("} -> ident %#v", _ident)
	}()
	if username, password, ok := userCredentialsFromContext(ctx); ok {
		if username == c.a.adminUsername && password == c.a.adminPassword {
			logger.Debugf("admin login success as %q", AdminUsername)
			return &Identity{
				id: store.Identity{
					Username: AdminUsername,
				},
				a: c.a,
			}, nil, nil
		}
		return nil, nil, errgo.WithCausef(nil, params.ErrUnauthorized, "invalid credentials")
	}
	return nil, []checkers.Caveat{
		checkers.NeedDeclaredCaveat(
			checkers.Caveat{
				Location:  c.a.location,
				Condition: "is-authenticated-user",
			},
			"username",
		),
	}, nil
}

// CheckUserDomain checks that the given user name has
// a valid domain name with respect to the given context
// (see also ContextWithRequiredDomain).
func CheckUserDomain(ctx context.Context, username string) error {
	domain, ok := ctx.Value(requiredDomainKey).(string)
	if ok && !strings.HasSuffix(username, "@"+domain) {
		return errgo.Newf("%q not in required domain %q", username, domain)
	}
	return nil
}

// DeclaredIdentity implements bakery.IdentityClient.DeclaredIdentity by
// retrieving the user information from the declared map.
func (c identityClient) DeclaredIdentity(ctx context.Context, declared map[string]string) (bakery.Identity, error) {
	username, ok := declared["username"]
	if !ok {
		return nil, errgo.Newf("no declared user")
	}
	if err := CheckUserDomain(ctx, username); err != nil {
		return nil, errgo.Mask(err)
	}
	return &Identity{
		id: store.Identity{
			Username: username,
		},
		a: c.a,
	}, nil
}

// An Identity is the implementation of bakery.Identity used in the
// identity server.
type Identity struct {
	id             store.Identity
	a              *Authorizer
	resolvedGroups []string
}

// Id implements bakery.Identity.Id.
func (id *Identity) Id() string {
	return string(id.id.Username)
}

// Domain implements bakery.Identity.Domain.
func (id *Identity) Domain() string {
	return ""
}

// Allow implements bakery.ACLIdentity.Allow by checking whether the
// given identity is in any of the required groups or users.
func (id *Identity) Allow(ctx context.Context, acl []string) (bool, error) {
	logger.Debugf("Identity.Allow %q, acl %q {", id, acl)
	defer logger.Debugf("}")
	if ok, isTrivial := trivialAllow(id.id.Username, acl); isTrivial {
		logger.Debugf("trivial %v", ok)
		return ok, nil
	}
	groups, err := id.Groups(ctx)
	if err != nil {
		logger.Debugf("error getting groups: %v", err)
		return false, errgo.Mask(err)
	}
	for _, a := range acl {
		for _, g := range groups {
			if g == a {
				logger.Infof("success (group %q)", g)
				return true, nil
			}
		}
	}
	logger.Debugf("not in groups")
	return false, nil
}

// Groups returns all the groups associated with the user. The groups
// include those stored in the identity server's database along with any
// retrieved by the relevent identity provider's GetGroups method. Once
// the set of groups has been determined it is cached in the Identity.
func (id *Identity) Groups(ctx context.Context) ([]string, error) {
	if id.resolvedGroups != nil {
		return id.resolvedGroups, nil
	}
	if err := id.lookup(ctx); err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	groups := id.id.Groups
	provider, _ := id.id.ProviderID.Split()
	if gr := id.a.groupResolvers[provider]; gr != nil {
		var err error
		groups, err = gr.resolveGroups(ctx, &id.id)
		if err != nil {
			logger.Warningf("error resolving groups: %s", err)
		} else {
			id.resolvedGroups = groups
		}
	}
	return groups, nil
}

func (id *Identity) lookup(ctx context.Context) error {
	if id.id.ID != "" {
		return nil
	}
	if err := id.a.store.Identity(ctx, &id.id); err != nil {
		if errgo.Cause(err) == store.ErrNotFound {
			return errgo.WithCausef(err, params.ErrNotFound, "")
		}
		return errgo.Mask(err)
	}
	return nil
}

// trivialAllow reports whether the username should be allowed
// access to the given ACL based on a superficial inspection
// of the ACL. If there is a definite answer, it will return
// a true isTrivial; otherwise it will return (false, false).
func trivialAllow(username string, acl []string) (allow, isTrivial bool) {
	if len(acl) == 0 {
		return false, true
	}
	for _, name := range acl {
		if name == "everyone" || name == username {
			return true, true
		}
	}
	return false, false
}

func UserOp(u params.Username, action string) bakery.Op {
	return op(kindUser+"-"+string(u), action)
}

func GlobalOp(action string) bakery.Op {
	return op(kindGlobal, action)
}

func op(entity, action string) bakery.Op {
	return bakery.Op{
		Entity: entity,
		Action: action,
	}
}

func splitEntity(entity string) (string, string) {
	if i := strings.Index(entity, "-"); i > 0 {
		return entity[0:i], entity[i+1:]
	}
	return entity, ""
}

// A groupResolver is used to update the groups associated with an
// identity.
type groupResolver interface {
	// resolveGroups returns the group information for the given
	// identity. If a non-nil error is returned it will be logged,
	// but the returned list of groups will still be taken as the set
	// of groups to be associated with the identity.
	resolveGroups(context.Context, *store.Identity) ([]string, error)
}

type idpGroupResolver struct {
	idp idp.IdentityProvider
}

// resolveGroups implements groupResolver by getting the groups from the
// idp and adding them to the set stored in the identity server.
func (r idpGroupResolver) resolveGroups(ctx context.Context, id *store.Identity) ([]string, error) {
	groups, err := r.idp.GetGroups(ctx, id)
	if err != nil {
		// if we couldn't get the groups just return the ones stored in the database.
		return id.Groups, errgo.Mask(err)
	}
	return uniqueStrings(append(groups, id.Groups...)), nil
}

// uniqueStrings removes all duplicates from the supplied
// string slice, updating the slice in place.
// The values will be in lexicographic order.
func uniqueStrings(ss []string) []string {
	if len(ss) < 2 {
		return ss
	}
	sort.Strings(ss)
	prev := ss[0]
	out := ss[:1]
	for _, s := range ss[1:] {
		if s == prev {
			continue
		}
		out = append(out, s)
		prev = s
	}
	return out
}
