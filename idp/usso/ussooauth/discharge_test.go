// Copyright 2015 Canonical Ltd.

package ussooauth_test

import (
	"net/http"
	"net/url"

	"github.com/garyburd/go-oauth/oauth"
	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"

	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idptest"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
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
	s.AssertDischarge(c, s.oauthVisit(c), checkers.New(
		checkers.TimeBefore,
	))
}

// oauthVisit returns a visit function that will sign a response to the return_to url
// with the oauth credentials provided.
func (s *dischargeSuite) oauthVisit(c *gc.C) func(*url.URL) error {
	return func(u *url.URL) error {
		var lm params.LoginMethods
		if err := idputil.GetLoginMethods(s.HTTPRequestClient, u, &lm); err != nil {
			return errgo.Mask(err)
		}
		uOAuth, err := url.Parse(lm.UbuntuSSOOAuth)
		if err != nil {
			return err
		}
		q := uOAuth.Query()
		uOAuth.RawQuery = ""
		resp, err := s.client.Get(s.HTTPClient, s.token, uOAuth.String(), q)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		var perr params.Error
		err = httprequest.UnmarshalJSONResponse(resp, &perr)
		c.Assert(err, gc.IsNil)
		return &perr
	}
}
