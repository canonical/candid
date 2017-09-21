// Copyright 2017 Canonical Ltd.

package admincmd_test

import (
	"net/http"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient"
	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/bakerytest"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent"
	macaroon "gopkg.in/macaroon.v2-unstable"
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

// AgentDischarger is a bakerytest.Discharger that implements
// visit by providing the agent login flow.
type AgentDischarger struct {
	*bakerytest.Discharger
	bakery *bakery.Bakery
	agents map[string]*bakery.PublicKey
}

// NewAgentDischarger creates an AgentDischarger.
func NewAgentDischarger() *AgentDischarger {
	d := &AgentDischarger{
		Discharger: bakerytest.NewDischarger(nil),
		bakery: bakery.New(bakery.BakeryParams{
			Key:            &agentBakeryKey,
			IdentityClient: agentLoginIdentityClient{},
			Authorizer:     bakery.OpenAuthorizer,
		}),
		agents: make(map[string]*bakery.PublicKey),
	}
	srv := &httprequest.Server{
		ErrorMapper: httpbakery.ErrorToResponse,
	}
	d.Discharger.Checker = httpbakery.ThirdPartyCaveatCheckerFunc(d.CheckThirdPartyCaveat)
	d.Discharger.AddHTTPHandlers([]httprequest.Handler{srv.Handle(d.visit)})
	return d
}

// agentMacaroonRequest represents a request to get the
// agent macaroon that, when discharged, becomes
// the discharge token to complete the discharge.
type agentMacaroonRequest struct {
	httprequest.Route `httprequest:"GET /login/agent"`
	Username          string            `httprequest:"username,form"`
	PublicKey         *bakery.PublicKey `httprequest:"public-key,form"`
}

type agentMacaroonResponse struct {
	Macaroon *bakery.Macaroon `json:"macaroon"`
}

// visit implements http.Handler. It performs the agent login interaction flow.
func (d *AgentDischarger) visit(p httprequest.Params, req *agentMacaroonRequest) (*agentMacaroonResponse, error) {
	m, err := d.bakery.Oven.NewMacaroon(
		p.Context,
		httpbakery.RequestVersion(p.Request),
		time.Now().Add(time.Minute),
		[]checkers.Caveat{
			idmclient.UserDeclaration(req.Username),
			bakery.LocalThirdPartyCaveat(req.PublicKey, httpbakery.RequestVersion(p.Request)),
		},
		bakery.LoginOp,
	)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &agentMacaroonResponse{
		Macaroon: m,
	}, nil
}

func (d *AgentDischarger) CheckThirdPartyCaveat(ctx context.Context, req *http.Request, info *bakery.ThirdPartyCaveatInfo, token *httpbakery.DischargeToken) ([]checkers.Caveat, error) {
	if token == nil || token.Kind != "agent" {
		ierr := httpbakery.NewInteractionRequiredError(nil, req)
		agent.SetInteraction(ierr, "/login/agent")
		return nil, ierr
	}
	var ms macaroon.Slice
	if err := ms.UnmarshalBinary(token.Value); err != nil {
		return nil, errgo.Mask(err)
	}
	ai, err := d.bakery.Checker.Auth(ms).Allow(ctx, bakery.LoginOp)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return []checkers.Caveat{
		idmclient.UserDeclaration(ai.Identity.Id()),
	}, nil
}

type agentLoginIdentityClient struct{}

func (c agentLoginIdentityClient) IdentityFromContext(ctx context.Context) (bakery.Identity, []checkers.Caveat, error) {
	return nil, nil, nil
}

func (c agentLoginIdentityClient) DeclaredIdentity(ctx context.Context, declared map[string]string) (bakery.Identity, error) {
	username, ok := declared["username"]
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
