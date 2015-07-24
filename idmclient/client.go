// Copyright 2015 Canonical Ltd.

package idmclient

import (
	"io"
	"net/http"
	"net/url"

	"github.com/CanonicalLtd/usso"
	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/httpbakery"

	"github.com/CanonicalLtd/blues-identity/params"
)

const (
	Production = "https://api.jujucharms.com/identity"
	Staging    = "https://api.staging.jujucharms.com/identity"
)

// Client represents the client of an identity server.
type Client struct {
	client
}

// NewParams holds the parameters for creating a new client.
type NewParams struct {
	BaseURL string
	Client  *httpbakery.Client

	// AuthUsername holds the username for admin login.
	AuthUsername string

	// AuthPassword holds the password for admin login.
	AuthPassword string
}

// New returns a new client.
func New(p NewParams) *Client {
	var c Client
	c.Client.BaseURL = p.BaseURL
	if p.AuthUsername != "" {
		c.Client.Doer = &basicAuthClient{
			client:   p.Client,
			user:     p.AuthUsername,
			password: p.AuthPassword,
		}
	} else {
		c.Client.Doer = p.Client
	}
	c.Client.UnmarshalError = httprequest.ErrorUnmarshaler(new(params.Error))
	return &c
}

// basicAuthClient wraps a bakery.Client, adding a basic auth
// header to every request.
type basicAuthClient struct {
	client   *httpbakery.Client
	user     string
	password string
}

func (c *basicAuthClient) Do(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(c.user, c.password)
	return c.client.Do(req)
}

func (c *basicAuthClient) DoWithBody(req *http.Request, r io.ReadSeeker) (*http.Response, error) {
	req.SetBasicAuth(c.user, c.password)
	return c.client.DoWithBody(req, r)
}

// UbuntuSSOOAuthVisitWebPage returns a function that can be used with
// httpbakey.Client.VisitWebPage to perform an OAuth login interaction.
func UbuntuSSOOAuthVisitWebPage(client *http.Client, tok *usso.SSOData) func(u *url.URL) error {
	return func(u *url.URL) error {
		return ussoOAuthVisit(client, tok, u)
	}
}

func ussoOAuthVisit(client *http.Client, tok *usso.SSOData, u *url.URL) error {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return errgo.Notef(err, "cannot create request")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return errgo.Notef(err, "cannot do request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var herr httpbakery.Error
		if err := httprequest.UnmarshalJSONResponse(resp, &herr); err != nil {
			return errgo.Notef(err, "cannot unmarshal error")
		}
		return &herr
	}
	var lm params.LoginMethods
	if err := httprequest.UnmarshalJSONResponse(resp, &lm); err != nil {
		return errgo.Notef(err, "cannot unmarshal login methods")
	}
	if lm.UbuntuSSOOAuth == "" {
		return errgo.New("Ubuntu SSO OAuth login not supported")
	}
	req, err = http.NewRequest("GET", lm.UbuntuSSOOAuth, nil)
	if err != nil {
		return errgo.Notef(err, "cannot create request")
	}
	base := *req.URL
	base.RawQuery = ""
	rp := usso.RequestParameters{
		HTTPMethod:      req.Method,
		BaseURL:         base.String(),
		Params:          req.URL.Query(),
		SignatureMethod: usso.HMACSHA1{},
	}
	if err := tok.SignRequest(&rp, req); err != nil {
		return errgo.Notef(err, "cannot sign request")
	}
	resp, err = client.Do(req)
	if err != nil {
		return errgo.Notef(err, "cannot do request")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var herr httpbakery.Error
	if err := httprequest.UnmarshalJSONResponse(resp, &herr); err != nil {
		return errgo.Notef(err, "cannot unmarshal error")
	}
	return &herr
}

//go:generate httprequest-generate-client github.com/CanonicalLtd/blues-identity/internal/v1 apiHandler client
