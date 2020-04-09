// Copyright 2015 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package candidclient

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/canonical/candid/params"
)

// Note: tests for this code are in the server implementation.

const (
	// Production holds the URL of the production jujucharms candid
	// server.
	Production = "https://api.jujucharms.com/identity"

	// Staging holds the URL of the staging jujucharms candid server.
	Staging = "https://api.staging.jujucharms.com/identity"
)

// Client represents the client of an identity server.
// It implements the identchecker.IdentityClient interface, so can
// be used directly to provide authentication for macaroon-based
// services.
type Client struct {
	client

	// permChecker is used to check group membership.
	// It is only non-zero when groups are enabled.
	permChecker *PermChecker

	useUserID bool
}

var _ identchecker.IdentityClient = (*Client)(nil)

// NewParams holds the parameters for creating a new client.
type NewParams struct {
	// BaseURL holds the URL of the identity manager.
	BaseURL string

	// Client holds the client to use to make requests
	// to the identity manager.
	Client *httpbakery.Client

	// AgentUsername holds the username for group-fetching authorization.
	// If this is empty, no group information will be provided.
	// The agent key is expected to be held inside the Client.
	AgentUsername string

	// CacheTime holds the maximum duration for which
	// group membership information will be cached.
	// If this is zero, group membership information will not be cached.
	CacheTime time.Duration

	// If UseUserID is true then the macaroons will use unique user
	// ID to transfer identity information rather than usernames.
	UseUserID bool
}

// New returns a new client.
func New(p NewParams) (*Client, error) {
	var c Client
	_, err := url.Parse(p.BaseURL)
	if p.BaseURL == "" || err != nil {
		return nil, errgo.Newf("bad identity client base URL %q", p.BaseURL)
	}
	c.Client.BaseURL = p.BaseURL
	if p.AgentUsername != "" {
		if err := agent.SetUpAuth(p.Client, &agent.AuthInfo{
			Key: p.Client.Key,
			Agents: []agent.Agent{{
				URL:      p.BaseURL,
				Username: p.AgentUsername,
			}},
		}); err != nil {
			return nil, errgo.Notef(err, "cannot set up agent authentication")
		}
		c.permChecker = NewPermChecker(&c, p.CacheTime)
	}
	c.Client.Doer = p.Client
	c.Client.UnmarshalError = httprequest.ErrorUnmarshaler(new(params.Error))
	c.useUserID = p.UseUserID
	return &c, nil
}

// IdentityFromContext implements identchecker.IdentityClient.IdentityFromContext
// by returning caveats created by IdentityCaveats.
func (c *Client) IdentityFromContext(ctx context.Context) (identchecker.Identity, []checkers.Caveat, error) {
	if c.useUserID {
		return nil, IdentityUserIDCaveats(c.Client.BaseURL), nil
	}
	return nil, IdentityCaveats(c.Client.BaseURL), nil
}

// DeclaredIdentity implements IdentityClient.DeclaredIdentity.
// On success, it returns a value that implements Identity as
// well as identchecker.Identity.
func (c *Client) DeclaredIdentity(ctx context.Context, declared map[string]string) (identchecker.Identity, error) {
	if c.useUserID {
		return c.declaredUserIDIdentity(ctx, declared)
	}
	username := declared["username"]

	if username == "" {
		return nil, errgo.Newf("no declared user name in %q", declared)
	}

	return &usernameIdentity{
		client:   c,
		username: username,
	}, nil
}

func (c *Client) declaredUserIDIdentity(ctx context.Context, declared map[string]string) (identchecker.Identity, error) {
	userid := declared["userid"]
	if userid == "" {
		return nil, errgo.Newf("no declared user id in %q", declared)
	}
	return &useridIdentity{
		client: c,
		user: params.User{
			ExternalID: userid,
		},
	}, nil
}

// CacheEvict evicts username from the user info cache.
func (c *Client) CacheEvict(username string) {
	if c.permChecker != nil {
		c.permChecker.CacheEvict(username)
	}
}

// CacheEvictAll evicts everything from the user info cache.
func (c *Client) CacheEvictAll() {
	if c.permChecker != nil {
		c.permChecker.CacheEvictAll()
	}
}

// LoginMethods returns information about the available login methods
// for the given URL, which is expected to be a URL as passed to
// a VisitWebPage function during the macaroon bakery discharge process.
func LoginMethods(client *http.Client, u *url.URL) (*params.LoginMethods, error) {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, errgo.Notef(err, "cannot create request")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errgo.Notef(err, "cannot do request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var herr httpbakery.Error
		if err := httprequest.UnmarshalJSONResponse(resp, &herr); err != nil {
			return nil, errgo.Notef(err, "cannot unmarshal error")
		}
		return nil, &herr
	}
	var lm params.LoginMethods
	if err := httprequest.UnmarshalJSONResponse(resp, &lm); err != nil {
		return nil, errgo.Notef(err, "cannot unmarshal login methods")
	}
	return &lm, nil
}

// IdentityCaveats returns a slice containing a third party
// "is-authenticated-user" caveat addressed to the identity server at
// the given URL that will authenticate the user with discharged. The
// user can be determined by calling Client.DeclaredIdentity on the
// declarations made by the discharge macaroon,
func IdentityCaveats(url string) []checkers.Caveat {
	return []checkers.Caveat{
		checkers.NeedDeclaredCaveat(
			checkers.Caveat{
				Location:  url,
				Condition: "is-authenticated-user",
			},
			"username",
		),
	}
}

// UserDeclaration returns a first party caveat that can be used
// by an identity manager to declare an identity on a discharge
// macaroon.
func UserDeclaration(username string) checkers.Caveat {
	return checkers.DeclaredCaveat("username", username)
}

// IdentityUserIDCaveats returns a slice containing a third party
// "is-authenticated-userid" caveat addressed to the identity server at
// the given URL that will authenticate the user with discharged. The
// user can be determined by calling Client.DeclaredIdentity on the
// declarations made by the discharge macaroon,
func IdentityUserIDCaveats(url string) []checkers.Caveat {
	return []checkers.Caveat{
		checkers.NeedDeclaredCaveat(
			checkers.Caveat{
				Location:  url,
				Condition: "is-authenticated-userid",
			},
			"userid",
		),
	}
}

// UserIDDeclaration returns a first party caveat that can be used by an
// identity manager to declare an identity on a discharge macaroon.
func UserIDDeclaration(id string) checkers.Caveat {
	return checkers.DeclaredCaveat("userid", id)
}

//go:generate httprequest-generate-client ../internal/v1 handler client
