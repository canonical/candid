// Copyright 2014 Canonical Ltd.

package store

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/juju/idmclient/params"
	"github.com/juju/utils"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
)

const (
	AdminUsername     = "admin@idm"
	SSHKeyGetterGroup = "sshkeygetter@idm"
	GroupListGroup    = "grouplist@idm"
)

// CheckAdminCredentials checks if the request has credentials that match the
// configured administration credentials for the server. If the credentials match
// nil will be reurned, otherwise the error will describe the failure.
//
// If there are no credentials in the request, it returns params.ErrNoAdminCredsProvided.
func (s *Store) CheckAdminCredentials(req *http.Request) error {
	if _, ok := req.Header["Authorization"]; !ok {
		return params.ErrNoAdminCredsProvided
	}
	u, p, err := utils.ParseBasicAuthHeader(req.Header)
	if err != nil {
		return errgo.WithCausef(err, params.ErrUnauthorized, "")
	}
	if u != s.pool.params.AuthUsername {
		return errgo.WithCausef(nil, params.ErrUnauthorized, "invalid credentials")
	}
	if p != s.pool.params.AuthPassword {
		return errgo.WithCausef(nil, params.ErrUnauthorized, "invalid credentials")
	}
	return nil
}

// UserHasPublicKeyCaveat creates a first-party caveat that ensures that
// the given user is associated with the given public key.
func UserHasPublicKeyCaveat(user params.Username, pk *bakery.PublicKey) checkers.Caveat {
	return checkers.Caveat{
		Condition: "user-has-public-key " + string(user) + " " + pk.String(),
	}
}

// UserHasPublicKeyChecker is a checker for the "user-has-public-key"
// caveat.
type UserHasPublicKeyChecker struct {
	// Store is used to lookup the specified user id.
	Store *Store

	// Identity can be used to save the retrieved identity for
	// later processing. If Identity is not nil then the retrieved
	// identity will be stored there, It is the caller's responsibility
	// to check that this contains the expected identity after
	// processing.
	Identity **mongodoc.Identity
}

// Condition implements checkers.Checker.Condition.
func (UserHasPublicKeyChecker) Condition() string {
	return "user-has-public-key"
}

// Check implements checkers.Checker.Check.
func (c UserHasPublicKeyChecker) Check(_, arg string) error {
	parts := strings.Fields(arg)
	if len(parts) != 2 {
		return errgo.New("caveat badly formatted")
	}
	var username params.Username
	err := username.UnmarshalText([]byte(parts[0]))
	if err != nil {
		return errgo.Mask(err)
	}
	var publicKey bakery.PublicKey
	err = publicKey.UnmarshalText([]byte(parts[1]))
	if err != nil {
		return errgo.Notef(err, "invalid public key %q", parts[1])
	}
	return c.checkUserPublicKey(username, &publicKey)
}

func (c UserHasPublicKeyChecker) checkUserPublicKey(username params.Username, publicKey *bakery.PublicKey) error {
	id, err := c.Store.GetIdentity(username)
	if err != nil {
		if errgo.Cause(err) != params.ErrNotFound {
			return errgo.Mask(err)
		}
		return errgo.Newf("public key not valid for user")
	}
	for _, pk := range id.PublicKeys {
		if !bytes.Equal(pk.Key, publicKey.Key[:]) {
			continue
		}
		if c.Identity != nil {
			*c.Identity = id
		}
		return nil
	}
	return errgo.Newf("public key not valid for user")
}

// CheckACL ensures that the logged in user is a member of a group
// specified in the ACL.
func (s *Store) CheckACL(c checkers.Checker, req *http.Request, acl []string) error {
	logger.Debugf("attemting to validate request for with acl %#v", acl)
	groups, err := s.GroupsFromRequest(c, req)
	if err != nil {
		return err
	}
	logger.Debugf("request groups: %#v", groups)
	for _, g := range groups {
		for _, a := range acl {
			if a == g {
				logger.Debugf("request allowed: requester has group %q", a)
				return nil
			}
		}
	}
	logger.Debugf("request denied")
	return errgo.WithCausef(nil, params.ErrForbidden, "user does not have correct permissions")
}

// GroupsFromRequest gets a list of groups the user belongs to from the request.
// if the request has the correct Basic authentication credentials for the admin user
// then it is in the group admin@idm.
func (s *Store) GroupsFromRequest(c checkers.Checker, req *http.Request) ([]string, error) {
	err := s.CheckAdminCredentials(req)
	if err == nil {
		logger.Debugf("admin credentials found.")
		return []string{AdminUsername}, nil
	}
	if errgo.Cause(err) != params.ErrNoAdminCredsProvided {
		logger.Debugf("invalid admin credentials supplied: %s", err)
		return nil, errgo.Mask(err, errgo.Is(params.ErrUnauthorized))
	}
	var identity *mongodoc.Identity
	attrs, verr := httpbakery.CheckRequest(s.Service, req, nil, checkers.New(
		c,
		UserHasPublicKeyChecker{Store: s, Identity: &identity},
	))
	if verr == nil {
		logger.Debugf("macaroon found for user %q", attrs["username"])
		if identity == nil || string(identity.Username) != attrs["username"] {
			var err error
			identity, err = s.GetIdentity(params.Username(attrs["username"]))
			if err != nil {
				return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
			}
		}
		return append(identity.Groups, string(identity.Username)), nil
	}
	logger.Debugf("no identity found, requesting login")
	m, err := s.Service.NewMacaroon(httpbakery.RequestVersion(req), []checkers.Caveat{
		checkers.DenyCaveat("discharge"),
		checkers.NeedDeclaredCaveat(
			checkers.Caveat{
				Location:  s.pool.params.Location,
				Condition: "is-authenticated-user",
			},
			"username"),
	})
	if err != nil {
		return nil, errgo.Notef(err, "cannot create macaroon")
	}
	mpath, err := RelativeURLPath(req.URL.Path, "/")
	if err != nil {
		return nil, errgo.Mask(err)
	}
	err = httpbakery.NewDischargeRequiredErrorForRequest(m, mpath, verr, req)
	err.(*httpbakery.Error).Info.CookieNameSuffix = "idm"
	return nil, err
}

// TODO(mhilton) RelativeURLPath was copy & pasted from charmstore. It
// should be moved to a shared location and included in both.

// RelativeURLPath returns a relative URL path that is lexically equivalent to
// targpath when interpreted by url.URL.ResolveReference.
// On succes, the returned path will always be relative to basePath, even if basePath
// and targPath share no elements. An error is returned if targPath can't
// be made relative to basePath (for example when either basePath
// or targetPath are non-absolute).
func RelativeURLPath(basePath, targPath string) (string, error) {
	if !strings.HasPrefix(basePath, "/") {
		return "", errgo.Newf("non-absolute base URL")
	}
	if !strings.HasPrefix(targPath, "/") {
		return "", errgo.Newf("non-absolute target URL")
	}
	baseParts := strings.Split(basePath, "/")
	targParts := strings.Split(targPath, "/")

	// For the purposes of dotdot, the last element of
	// the paths are irrelevant. We save the last part
	// of the target path for later.
	lastElem := targParts[len(targParts)-1]
	baseParts = baseParts[0 : len(baseParts)-1]
	targParts = targParts[0 : len(targParts)-1]

	// Find the common prefix between the two paths:
	var i int
	for ; i < len(baseParts); i++ {
		if i >= len(targParts) || baseParts[i] != targParts[i] {
			break
		}
	}
	dotdotCount := len(baseParts) - i
	targOnly := targParts[i:]
	result := make([]string, 0, dotdotCount+len(targOnly)+1)
	for i := 0; i < dotdotCount; i++ {
		result = append(result, "..")
	}
	result = append(result, targOnly...)
	result = append(result, lastElem)
	return strings.Join(result, "/"), nil
}
