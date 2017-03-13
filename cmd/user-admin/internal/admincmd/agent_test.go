// Copyright 2017 Canonical Ltd.

package admincmd_test

import (
	"net/http"

	"github.com/juju/httprequest"
	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/bakerytest"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent"
)

var agentBakeryKey bakery.KeyPair

func init() {
	if err := agentBakeryKey.Public.UnmarshalText([]byte("VM/0uXz4QvXJ7AB0F2RJaIuPqpgoQNYySeNEjUePyls=")); err != nil {
		panic(err)
	}
	if err := agentBakeryKey.Private.UnmarshalText([]byte("xctCL3iB2Qa9fvjGOPKU/3GHYMiqd4KJSF4Z44SGyRo=")); err != nil {
		panic(err)
	}
}

// AgentDischarger is a bakerytest.InteractiveDischarger that implements
// visit by providing the agent login flow.
type AgentDischarger struct {
	*bakerytest.InteractiveDischarger
	bakery *bakery.Bakery
	agents map[string]*bakery.PublicKey
}

// NewAgentDischarger creates an AgentDischarger.
func NewAgentDischarger() *AgentDischarger {
	d := &AgentDischarger{
		bakery: bakery.New(bakery.BakeryParams{
			Key:            &agentBakeryKey,
			IdentityClient: agentLoginIdentityClient{},
		}),
		agents: make(map[string]*bakery.PublicKey),
	}
	d.InteractiveDischarger = bakerytest.NewInteractiveDischarger(nil, http.HandlerFunc(d.visit))
	return d
}

// SetPublicKey sets the given agent's public key.
func (d *AgentDischarger) SetPublicKey(username string, k *bakery.PublicKey) {
	if k == nil {
		panic("nil key")
	}
	d.agents[username] = k
}

// visit implements http.Handler. It performs the agent login interaction flow.
func (d *AgentDischarger) visit(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Accept") == "application/json" {
		httprequest.WriteJSON(w, http.StatusOK, map[string]string{"agent": req.RequestURI})
		return
	}
	ctx := context.Background()
	if err := d.visit1(ctx, w, req); err != nil {
		d.FinishInteraction(ctx, w, req, nil, err)
		status, body := httpbakery.ErrorToResponse(ctx, err)
		httprequest.WriteJSON(w, status, body)
	}
}

func (d *AgentDischarger) visit1(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	user, key, err := agent.LoginCookie(req)
	if err != nil {
		return errgo.Notef(err, "invalid agent cookie")
	}
	if key1, ok := d.agents[user]; !ok || *key != *key1 {
		return errgo.Newf("unrecognized agent credentials for %q", user)
	}
	version := httpbakery.RequestVersion(req)
	ctx = context.WithValue(ctx, usernameKey, user)
	ctx = context.WithValue(ctx, publicKeyKey, key)
	ctx = context.WithValue(ctx, versionKey, version)
	ai, authErr := d.bakery.Checker.Auth(httpbakery.RequestMacaroons(req)...).Allow(ctx, bakery.LoginOp)
	if authErr == nil {
		d.FinishInteraction(ctx, w, req, []checkers.Caveat{checkers.DeclaredCaveat("username", ai.Identity.Id())}, nil)
		httprequest.WriteJSON(w, http.StatusOK, agentResponse{
			AgentLogin: true,
		})
		return nil
	}
	derr, ok := errgo.Cause(authErr).(*bakery.DischargeRequiredError)
	if !ok {
		return errgo.Mask(authErr, errgo.Is(httpbakery.ErrBadRequest))
	}
	m, err := d.bakery.Oven.NewMacaroon(ctx, version, ages, derr.Caveats, derr.Ops...)
	if err != nil {
		return errgo.Notef(err, "cannot create macaroon")
	}
	httpbakery.WriteDischargeRequiredErrorForRequest(w, m, "", authErr, req)
	return nil
}

// agentResponse contains the response to an agent login attempt.
type agentResponse struct {
	AgentLogin bool `json:"agent_login"`
}

type agentLoginContextKey int

const (
	usernameKey agentLoginContextKey = iota
	publicKeyKey
	versionKey
)

type agentLoginIdentityClient struct{}

func (c agentLoginIdentityClient) IdentityFromContext(ctx context.Context) (bakery.Identity, []checkers.Caveat, error) {
	return nil, []checkers.Caveat{
		checkers.DeclaredCaveat("agent-username", ctx.Value(usernameKey).(string)),
		bakery.LocalThirdPartyCaveat(ctx.Value(publicKeyKey).(*bakery.PublicKey), ctx.Value(versionKey).(bakery.Version)),
	}, nil
}

func (c agentLoginIdentityClient) DeclaredIdentity(ctx context.Context, declared map[string]string) (bakery.Identity, error) {
	username, ok := declared["agent-username"]
	if !ok {
		return nil, errgo.Newf("no declared user")
	}
	return bakery.SimpleIdentity(username), nil
}

// IdentityClient creates an identity client that will authenticate with
// an AgentLogin being served by a InteractiveDischarger at the given
// location.
func IdentityClient(location string) bakery.IdentityClient {
	return &identityClient{
		location: location,
	}
}

type identityClient struct {
	location string
}

// IdentityFromContext implements bakery.IdentityClient.IdentityFromContext.
func (c identityClient) IdentityFromContext(ctx context.Context) (bakery.Identity, []checkers.Caveat, error) {
	return nil, []checkers.Caveat{{
		Location:  c.location,
		Condition: "is-authenticated-user",
	}}, nil
}

// DeclaredIdentity implements bakery.IdentityClient.DeclaredIdentity.
func (c identityClient) DeclaredIdentity(ctx context.Context, declared map[string]string) (bakery.Identity, error) {
	username, ok := declared["username"]
	if !ok {
		return nil, errgo.Newf("no declared user")
	}
	return bakery.SimpleIdentity(username), nil
}
