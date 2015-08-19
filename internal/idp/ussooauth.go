// Copyright 2015 Canonical Ltd.

package idp

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"regexp"

	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
)

// USSOOAuthIdentityProvider allows login using request signing with
// Ubuntu SSO OAuth tokens.
type USSOOAuthIdentityProvider struct{}

// Name gives the name of the identity provider (usso_oauth).
func (*USSOOAuthIdentityProvider) Name() string {
	return "usso_oauth"
}

// Description gives a description of the identity provider.
func (*USSOOAuthIdentityProvider) Description() string {
	return "Ubuntu SSO OAuth"
}

// Interactive specifies that this identity provider is not interactive.
func (*USSOOAuthIdentityProvider) Interactive() bool {
	return false
}

// URL gets the login URL to use this identity provider.
func (*USSOOAuthIdentityProvider) URL(c Context, waitID string) (string, error) {
	callback := c.IDPURL("/oauth")
	if waitID != "" {
		callback += "?waitid=" + waitID
	}
	return callback, nil
}

// Handle handles the Ubuntu SSO OAuth login process.
func (u *USSOOAuthIdentityProvider) Handle(c Context) {
	id, err := verifyOAuthSignature(c.RequestURL(), c.Params().Request)
	if err != nil {
		c.LoginFailure(err)
		return
	}
	var identity mongodoc.Identity
	if err := c.Store().DB.Identities().Find(bson.D{{"external_id", id}}).One(&identity); err != nil {
		c.LoginFailure(errgo.Notef(err, "cannot get user details for %q", id))
		return
	}
	loginIdentity(c, &identity)
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
