// Copyright 2015 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

// Package candidtest holds a mock implementation of the identity manager
// suitable for testing.
package candidtest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery/checkers"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery/identchecker"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakerytest"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery/agent"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/canonical/candid/candidclient"
	"github.com/canonical/candid/params"
)

// GroupListGroup is the group that users must belong to in order to
// enquire about other users' groups.
const GroupListGroup = "group-lister"

// Server represents a mock identity server.
// It currently serves only the discharge and groups endpoints.
type Server struct {
	// URL holds the URL of the mock identity server.
	// The discharger endpoint is located at URL/v1/discharge.
	URL *url.URL

	// PublicKey holds the public key of the mock identity server.
	PublicKey *bakery.PublicKey

	// Bakery holds the macaroon bakery used by
	// the mock server.
	Bakery *identchecker.Bakery

	discharger *bakerytest.Discharger

	// mu guards the fields below it.
	mu          sync.Mutex
	users       map[string]*user
	defaultUser string
}

type user struct {
	groups []string
	key    *bakery.KeyPair
}

// NewServer runs a mock identity server. It can discharge
// macaroons and return information on user group membership.
// The returned server should be closed after use.
func NewServer() *Server {
	srv := &Server{
		users: make(map[string]*user),
	}
	srv.discharger = bakerytest.NewDischarger(nil)
	srv.discharger.Checker = httpbakery.ThirdPartyCaveatCheckerFunc(srv.checkThirdPartyCaveat)
	u, err := url.Parse(srv.discharger.Location())
	if err != nil {
		panic(err)
	}
	srv.URL = u

	key, err := bakery.GenerateKey()
	if err != nil {
		panic(err)
	}
	srv.PublicKey = &key.Public
	srv.discharger.AddHTTPHandlers(reqServer.Handlers(srv.newHandler))
	srv.Bakery = identchecker.NewBakery(identchecker.BakeryParams{
		Checker:        checker,
		Locator:        srv,
		Key:            key,
		IdentityClient: identityClient{srv},
		Authorizer: identchecker.ACLAuthorizer{
			GetACL: srv.getACL,
		},
	})
	return srv
}

var reqServer = httprequest.Server{
	ErrorMapper: errToResp,
}

func errToResp(ctx context.Context, err error) (int, interface{}) {
	// Allow bakery errors to be returned as the bakery would
	// like them, so that httpbakery.Client.Do will work.
	if err, ok := errgo.Cause(err).(*httpbakery.Error); ok {
		return httpbakery.ErrorToResponse(ctx, err)
	}
	errorBody := errorResponseBody(err)
	status := http.StatusInternalServerError
	switch errorBody.Code {
	case params.ErrNotFound:
		status = http.StatusNotFound
	case params.ErrForbidden, params.ErrAlreadyExists:
		status = http.StatusForbidden
	case params.ErrBadRequest:
		status = http.StatusBadRequest
	case params.ErrUnauthorized, params.ErrNoAdminCredsProvided:
		status = http.StatusUnauthorized
	case params.ErrMethodNotAllowed:
		status = http.StatusMethodNotAllowed
	case params.ErrServiceUnavailable:
		status = http.StatusServiceUnavailable
	}
	return status, errorBody
}

// errorResponse returns an appropriate error response for the provided error.
func errorResponseBody(err error) *params.Error {
	errResp := &params.Error{
		Message: err.Error(),
	}
	cause := errgo.Cause(err)
	if coder, ok := cause.(errorCoder); ok {
		errResp.Code = coder.ErrorCode()
	} else if errgo.Cause(err) == httprequest.ErrUnmarshal {
		errResp.Code = params.ErrBadRequest
	}
	return errResp
}

type errorCoder interface {
	ErrorCode() params.ErrorCode
}

// Close shuts down the server.
func (srv *Server) Close() {
	srv.discharger.Close()
}

// PublicKeyForLocation implements bakery.PublicKeyLocator
// by returning the server's public key for all locations.
func (srv *Server) PublicKeyForLocation(loc string) (*bakery.PublicKey, error) {
	return srv.PublicKey, nil
}

// ThirdPartyInfo implements bakery.ThirdPartyLocator.ThirdPartyInfo.
func (srv *Server) ThirdPartyInfo(ctx context.Context, loc string) (bakery.ThirdPartyInfo, error) {
	return srv.discharger.ThirdPartyInfo(ctx, loc)
}

// UserPublicKey returns the key for the given user.
// It panics if the user has not been added.
func (srv *Server) UserPublicKey(username string) *bakery.KeyPair {
	u := srv.user(username)
	if u == nil {
		panic("no user found")
	}
	return u.key
}

// CandidClient returns an identity manager client that takes
// to the given server as the given user name.
func (srv *Server) CandidClient(username string) *candidclient.Client {
	c, err := candidclient.New(candidclient.NewParams{
		BaseURL:       srv.URL.String(),
		AgentUsername: username,
		Client:        srv.Client(username),
	})
	if err != nil {
		panic(err)
	}
	return c
}

// Client returns a bakery client that will discharge as the given user.
// If the user does not exist, it is added with no groups.
func (srv *Server) Client(username string) *httpbakery.Client {
	c := httpbakery.NewClient()
	u := srv.user(username)
	if u == nil {
		srv.AddUser(username)
		u = srv.user(username)
	}
	c.Key = u.key
	// Note that this duplicates the SetUpAuth that candidclient.New will do
	// but that shouldn't matter as SetUpAuth is idempotent.
	agent.SetUpAuth(c, &agent.AuthInfo{
		Key: u.key,
		Agents: []agent.Agent{{
			URL:      srv.URL.String(),
			Username: username,
		}},
	})
	return c
}

// SetDefaultUser configures the server so that it will discharge for
// the given user if no agent-login cookie is found. The user does not
// need to have been added. Note that this will bypass the
// VisitURL logic.
//
// If the name is empty, there will be no default user.
func (srv *Server) SetDefaultUser(name string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.defaultUser = name
}

// AddUser adds a new user that's in the given set of groups.
// If the user already exists, the given groups are
// added to that user's groups.
func (srv *Server) AddUser(name string, groups ...string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	u := srv.users[name]
	if u == nil {
		key, err := bakery.GenerateKey()
		if err != nil {
			panic(err)
		}
		srv.users[name] = &user{
			groups: groups,
			key:    key,
		}
		return
	}
	for _, g := range groups {
		found := false
		for _, ug := range u.groups {
			if ug == g {
				found = true
				break
			}
		}
		if !found {
			u.groups = append(u.groups, g)
		}
	}
}

// RemoveUsers removes all added users and resets the
// default user to nothing.
func (srv *Server) RemoveUsers() {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.users = make(map[string]*user)
	srv.defaultUser = ""
}

// RemoveUser removes the given user.
func (srv *Server) RemoveUser(user string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.users, user)
}

func (srv *Server) user(name string) *user {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.users[name]
}

func (srv *Server) getACL(ctx context.Context, op bakery.Op) ([]string, bool, error) {
	switch op.Action {
	case "login":
		return []string{identchecker.Everyone}, true, nil
	case "list-groups":
		return []string{strings.TrimPrefix(op.Entity, "user-"), GroupListGroup}, true, nil
	default:
		return nil, false, errgo.New("unrecognised operation")
	}
}

func (srv *Server) checkThirdPartyCaveat(ctx context.Context, req *http.Request, info *bakery.ThirdPartyCaveatInfo, token *httpbakery.DischargeToken) ([]checkers.Caveat, error) {
	if srv.defaultUser != "" {
		return []checkers.Caveat{
			candidclient.UserDeclaration(srv.defaultUser),
		}, nil
	}
	dischargeID := srv.dischargeID(info)
	ctx = contextWithDischargeID(ctx, dischargeID)
	if token == nil || token.Kind != "agent" {
		ierr := httpbakery.NewInteractionRequiredError(nil, req)
		agent.SetInteraction(ierr, "/login/agent?discharge-id="+dischargeID)
		return nil, ierr
	}
	var ms macaroon.Slice
	if err := ms.UnmarshalBinary(token.Value); err != nil {
		return nil, errgo.Mask(err)
	}
	ops, _, err := srv.Bakery.Oven.VerifyMacaroon(ctx, ms)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	username := ""
	for _, op := range ops {
		if strings.HasPrefix(op.Entity, "user-") && op.Action == "discharge" {
			username = strings.TrimPrefix(op.Entity, "user-")
			break
		}
	}
	_, err = srv.Bakery.Checker.Auth(ms).Allow(
		ctx,
		bakery.Op{
			Entity: "user-" + username,
			Action: "discharge",
		},
	)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return []checkers.Caveat{
		candidclient.UserDeclaration(username),
	}, nil
}

func (srv *Server) dischargeID(info *bakery.ThirdPartyCaveatInfo) string {
	sum := sha256.Sum256(info.Caveat)
	return fmt.Sprintf("%x", sum[:4])
}

func (srv *Server) newHandler(p httprequest.Params, req interface{}) (*handler, context.Context, error) {
	_, err := srv.Bakery.Checker.Auth(httpbakery.RequestMacaroons(p.Request)...).Allow(p.Context, srv.opForRequest(req))
	if err == nil {
		return &handler{srv}, p.Context, nil
	}
	derr, ok := errgo.Cause(err).(*bakery.DischargeRequiredError)
	if !ok {
		return nil, p.Context, errgo.Mask(err)
	}
	version := httpbakery.RequestVersion(p.Request)
	m, err := srv.Bakery.Oven.NewMacaroon(p.Context, version, derr.Caveats, derr.Ops...)
	if err != nil {
		return nil, p.Context, errgo.Notef(err, "cannot create macaroon")
	}
	return nil, p.Context, httpbakery.NewDischargeRequiredError(httpbakery.DischargeRequiredErrorParams{
		Macaroon:      m,
		OriginalError: err,
		Request:       p.Request,
	})
}

func (srv *Server) opForRequest(req interface{}) bakery.Op {
	switch r := req.(type) {
	case *agentMacaroonRequest:
		return agentLoginOp
	case *groupsRequest:
		return bakery.Op{
			Entity: "user-" + r.User,
			Action: "list-groups",
		}
	default:
		panic("unrecognised request")
	}
}

var agentLoginOp = bakery.Op{
	Entity: "agent",
	Action: "login",
}

type handler struct {
	srv *Server
}

type groupsRequest struct {
	httprequest.Route `httprequest:"GET /v1/u/:User/groups"`
	User              string `httprequest:",path"`
}

func (h handler) GetGroups(p httprequest.Params, req *groupsRequest) ([]string, error) {
	if u := h.srv.user(req.User); u != nil {
		return u.groups, nil
	}
	return nil, params.ErrNotFound
}

// agentMacaroonRequest represents a request to get the
// agent macaroon that, when discharged, becomes
// the discharge token to complete the discharge.
type agentMacaroonRequest struct {
	httprequest.Route `httprequest:"GET /login/agent"`
	Username          string            `httprequest:"username,form"`
	PublicKey         *bakery.PublicKey `httprequest:"public-key,form"`
	DischargeID       string            `httprequest:"discharge-id,form"`
}

type agentMacaroonResponse struct {
	Macaroon *bakery.Macaroon `json:"macaroon"`
}

// Visit implements http.Handler. It performs the agent login interaction flow.
func (h handler) Visit(p httprequest.Params, req *agentMacaroonRequest) (*agentMacaroonResponse, error) {
	m, err := h.srv.Bakery.Oven.NewMacaroon(
		p.Context,
		httpbakery.RequestVersion(p.Request),
		[]checkers.Caveat{
			dischargeIDCaveat(req.DischargeID),
			bakery.LocalThirdPartyCaveat(req.PublicKey, httpbakery.RequestVersion(p.Request)),
		},
		bakery.Op{
			Entity: "user-" + req.Username,
			Action: "discharge",
		},
	)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &agentMacaroonResponse{
		Macaroon: m,
	}, nil
}
