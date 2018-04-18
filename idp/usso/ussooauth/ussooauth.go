// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Pacakge ussooauth is an identity provider that authenticates against
// Ubuntu SSO using OAuth.
package ussooauth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1/ussologin"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idputil"
	"github.com/CanonicalLtd/candid/store"
)

func init() {
	idp.Register("usso_oauth", func(func(interface{}) error) (idp.IdentityProvider, error) {
		return IdentityProvider, nil
	})
}

// IdentityProvider is an idp.IdentityProvider that provides
// authentication via Ubuntu SSO using OAuth.
var IdentityProvider idp.IdentityProvider = &identityProvider{}

const (
	ussoURL = "https://login.ubuntu.com"
)

// identityProvider allows login using request signing with
// Ubuntu SSO OAuth tokens.
type identityProvider struct {
	initParams idp.InitParams
}

// Name gives the name of the identity provider (usso_oauth).
func (*identityProvider) Name() string {
	return "usso_oauth"
}

// Domain implements idp.IdentityProvider.Domain.
func (*identityProvider) Domain() string {
	return ""
}

// Description gives a description of the identity provider.
func (*identityProvider) Description() string {
	return "Ubuntu SSO OAuth"
}

// Interactive specifies that this identity provider is not interactive.
func (*identityProvider) Interactive() bool {
	return false
}

// Init initialises the identity provider.
func (idp *identityProvider) Init(_ context.Context, params idp.InitParams) error {
	idp.initParams = params
	return nil
}

// URL gets the login URL to use this identity provider.
func (idp *identityProvider) URL(dischargeID string) string {
	return idputil.URL(idp.initParams.URLPrefix, "/login", dischargeID)
}

// SetInteraction sets the interaction information for
func (idp *identityProvider) SetInteraction(ierr *httpbakery.Error, dischargeID string) {
	ussologin.SetInteraction(ierr, idputil.URL(idp.initParams.URLPrefix, "/interact", dischargeID))
}

//  GetGroups implements idp.IdentityProvider.GetGroups.
func (*identityProvider) GetGroups(context.Context, *store.Identity) ([]string, error) {
	// This method should never be called as this IDP supports
	// identities in the "usso" namespace.
	return nil, nil
}

// Handle handles the Ubuntu SSO OAuth login process.
func (idp *identityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	id, err := verifyOAuthSignature(idp.initParams.URLPrefix+req.URL.Path, req)
	if err != nil {
		idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
		return
	}
	identity := store.Identity{
		ProviderID: store.MakeProviderIdentity("usso", id),
	}
	if err := idp.initParams.Store.Identity(ctx, &identity); err != nil {
		idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), errgo.Notef(err, "cannot get user details for %q", id))
		return
	}
	if strings.TrimPrefix(req.URL.Path, idp.initParams.URLPrefix) == "/interact" {
		token, err := idp.initParams.DischargeTokenCreator.DischargeToken(ctx, &identity)
		if err != nil {
			code, body := httpbakery.ErrorToResponse(ctx, err)
			httprequest.WriteJSON(w, code, body)
			return
		}
		httprequest.WriteJSON(w, http.StatusOK, ussologin.LoginResponse{
			DischargeToken: token,
		})
	} else {
		idp.initParams.VisitCompleter.Success(ctx, w, req, idputil.DischargeID(req), &identity)
	}
}

var consumerKeyRegexp = regexp.MustCompile(`oauth_consumer_key="([^"]*)"`)

// verifyOAuthSignature verifies with Ubuntu SSO that the request is correctly
// signed.
func verifyOAuthSignature(requestURL string, req *http.Request) (string, error) {
	req.ParseForm()
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", errgo.Notef(err, "cannot parse request URL")
	}
	u.RawQuery = ""
	request := struct {
		URL           string `json:"http_url"`
		Method        string `json:"http_method"`
		Authorization string `json:"authorization"`
		QueryString   string `json:"query_string"`
	}{
		URL:           u.String(),
		Method:        req.Method,
		Authorization: req.Header.Get("Authorization"),
		QueryString:   req.Form.Encode(),
	}
	buf, err := json.Marshal(request)
	if err != nil {
		return "", errgo.Notef(err, "cannot marshal request")
	}
	resp, err := http.Post(ussoURL+"/api/v2/requests/validate", "application/json", bytes.NewReader(buf))
	if err != nil {
		return "", errgo.Mask(err)
	}
	defer resp.Body.Close()
	t, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return "", errgo.Newf("bad content type %q", resp.Header.Get("Content-Type"))
	}
	if t != "application/json" {
		return "", errgo.Newf("unexpected response type %q", t)
	}
	var validated struct {
		IsValid bool   `json:"is_valid"`
		Error   string `json:"error"`
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &validated); err != nil {
		return "", errgo.Mask(err)
	}
	if validated.Error != "" {
		return "", errgo.Newf("cannot validate OAuth credentials: %s", validated.Error)
	}
	if !validated.IsValid {
		return "", errgo.Newf("invalid OAuth credentials")
	}
	consumerKey := consumerKeyRegexp.FindStringSubmatch(req.Header.Get("Authorization"))
	if len(consumerKey) != 2 {
		return "", errgo.Newf("no customer key in authorization")
	}
	return ussoURL + "/+id/" + consumerKey[1], nil
}
