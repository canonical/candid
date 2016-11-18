// Copyright 2015 Canonical Ltd.

package ussooauth_test

import (
	"net/http"
	"net/url"

	"github.com/garyburd/go-oauth/oauth"
	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/agent"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/usso/internal/mockusso"
	"github.com/CanonicalLtd/blues-identity/idp/usso/ussooauth"
)

type dischargeSuite struct {
	idptest.DischargeSuite
	mockusso.Suite
	client *oauth.Client
	token  *oauth.Credentials
}

var _ = gc.Suite(&dischargeSuite{})

func (s *dischargeSuite) SetUpSuite(c *gc.C) {
	s.Suite.SetUpSuite(c)
	s.DischargeSuite.SetUpSuite(c)
}

func (s *dischargeSuite) TearDownSuite(c *gc.C) {
	s.DischargeSuite.TearDownSuite(c)
	s.Suite.TearDownSuite(c)
}

func (s *dischargeSuite) SetUpTest(c *gc.C) {
	s.Suite.SetUpTest(c)
	s.IDPs = []idp.IdentityProvider{
		agent.IdentityProvider,
		ussooauth.IdentityProvider,
	}
	s.DischargeSuite.SetUpTest(c)
}

func (s *dischargeSuite) TearDownTest(c *gc.C) {
	s.DischargeSuite.TearDownTest(c)
	s.Suite.TearDownTest(c)
}

func (s *dischargeSuite) TestDischarge(c *gc.C) {
	err := s.IDMClient.SetUser(&params.SetUserRequest{
		Username: "test",
		User: params.User{
			Username:   "test",
			ExternalID: "https://login.ubuntu.com/+id/1234",
			Email:      "test@example.com",
			FullName:   "Test User",
			IDPGroups: []string{
				"test",
			},
		},
	})
	c.Assert(err, gc.IsNil)
	s.MockUSSO.AddUser(&mockusso.User{
		ID:       "1234",
		NickName: "test",
		FullName: "Test User",
		Email:    "test@example.com",
		Groups: []string{
			"test",
		},
		ConsumerSecret: "secret1",
		TokenKey:       "test-token",
		TokenSecret:    "secret2",
	})
	s.MockUSSO.SetLoginUser("1234")
	s.client = &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  "1234",
			Secret: "secret1",
		},
		SignatureMethod: oauth.HMACSHA1,
	}
	s.token = &oauth.Credentials{
		Token:  "test-token",
		Secret: "secret2",
	}
	visitor := httpbakery.NewMultiVisitor(&oauthVisitor{
		c,
		s.client,
		s.token,
	})
	s.AssertDischarge(c, visitor, checkers.New(
		checkers.TimeBefore,
	))
}

type oauthVisitor struct {
	c      *gc.C
	client *oauth.Client
	token  *oauth.Credentials
}

// oauthVisit returns a visit function that will sign a response to the return_to url
// with the oauth credentials provided.
func (v *oauthVisitor) VisitWebPage(c *httpbakery.Client, m map[string]*url.URL) error {
	uOAuth, ok := m["usso_oauth"]
	if !ok {
		return httpbakery.ErrMethodNotSupported
	}
	q := uOAuth.Query()
	uOAuth.RawQuery = ""
	resp, err := v.client.Get(c.Client, v.token, uOAuth.String(), q)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var perr params.Error
	err = httprequest.UnmarshalJSONResponse(resp, &perr)
	v.c.Assert(err, gc.IsNil)
	return &perr
}
