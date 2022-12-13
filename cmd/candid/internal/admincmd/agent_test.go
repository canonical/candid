// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"context"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery/checkers"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery/identchecker"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakerytest"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery/agent"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/canonical/candid/candidclient"
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
	bakery *identchecker.Bakery
	agents map[string]*bakery.PublicKey
}

// NewAgentDischarger creates an AgentDischarger.
func NewAgentDischarger() *AgentDischarger {
	d := &AgentDischarger{
		Discharger: bakerytest.NewDischarger(nil),
		bakery: identchecker.NewBakery(identchecker.BakeryParams{
			Key:            &agentBakeryKey,
			IdentityClient: agentLoginIdentityClient{},
			Authorizer:     identchecker.OpenAuthorizer,
		}),
		agents: make(map[string]*bakery.PublicKey),
	}
	srv := &httprequest.Server{
		ErrorMapper: httpbakery.ErrorToResponse,
	}
	d.Discharger.CheckerP = d
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
		[]checkers.Caveat{
			candidclient.UserDeclaration(req.Username),
			bakery.LocalThirdPartyCaveat(req.PublicKey, httpbakery.RequestVersion(p.Request)),
		},
		identchecker.LoginOp,
	)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &agentMacaroonResponse{
		Macaroon: m,
	}, nil
}

func (d *AgentDischarger) CheckThirdPartyCaveat(ctx context.Context, p httpbakery.ThirdPartyCaveatCheckerParams) ([]checkers.Caveat, error) {
	if p.Token == nil || p.Token.Kind != "agent" {
		ierr := httpbakery.NewInteractionRequiredError(nil, p.Request)
		agent.SetInteraction(ierr, "/login/agent")
		return nil, ierr
	}
	var ms macaroon.Slice
	if err := ms.UnmarshalBinary(p.Token.Value); err != nil {
		return nil, errgo.Mask(err)
	}
	ai, err := d.bakery.Checker.Auth(ms).Allow(ctx, identchecker.LoginOp)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return []checkers.Caveat{
		candidclient.UserDeclaration(ai.Identity.Id()),
	}, nil
}

type agentLoginIdentityClient struct{}

func (c agentLoginIdentityClient) IdentityFromContext(ctx context.Context) (identchecker.Identity, []checkers.Caveat, error) {
	return nil, nil, nil
}

func (c agentLoginIdentityClient) DeclaredIdentity(ctx context.Context, declared map[string]string) (identchecker.Identity, error) {
	username, ok := declared["username"]
	if !ok {
		return nil, errgo.Newf("no declared user")
	}
	return identchecker.SimpleIdentity(username), nil
}

// IdentityClient creates an identity client that will authenticate with
// an AgentLogin being served by a InteractiveDischarger at the given
// location.
func IdentityClient(location string) identchecker.IdentityClient {
	return &identityClient{
		location: location,
	}
}

type identityClient struct {
	location string
}

// IdentityFromContext implements identchecker.IdentityClient.IdentityFromContext.
func (c identityClient) IdentityFromContext(ctx context.Context) (identchecker.Identity, []checkers.Caveat, error) {
	return nil, []checkers.Caveat{{
		Location:  c.location,
		Condition: "is-authenticated-user",
	}}, nil
}

// DeclaredIdentity implements identchecker.IdentityClient.DeclaredIdentity.
func (c identityClient) DeclaredIdentity(ctx context.Context, declared map[string]string) (identchecker.Identity, error) {
	username, ok := declared["username"]
	if !ok {
		return nil, errgo.Newf("no declared user")
	}
	return identchecker.SimpleIdentity(username), nil
}
