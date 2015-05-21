// Copyright 2014 Canonical Ltd.

package v1

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

type ussoProvider struct {
	*openid2Provider
	location string
	h        *Handler
}

const (
	ussoRealm = "" // TODO Doesn't work if this is non-empty; why? [A: http://openid.net/specs/openid-authentication-2_0.html#realms]
	ussoURL   = "https://login.ubuntu.com"
)

// TODO It should not be necessary to know all the possible
// groups in advance.
//
// This list needs to contain any private teams that the system needs to know about.
const openIdRequestedTeams = "blues-development,charm-beta"

func newUSSOProvider(h *Handler, location string) *ussoProvider {
	return &ussoProvider{
		openid2Provider: newOpenID2Provider(h, location+"/callback", ussoURL, ussoRealm),
		location:        location,
		h:               h,
	}
}

func (p *ussoProvider) oauthURL(waitid string) (string, error) {
	loginURL := p.location + "/oauth"
	if waitid != "" {
		loginURL += "?waitid=" + waitid
	}
	return loginURL, nil
}

func (p *ussoProvider) openIDURL(waitId string) (string, error) {
	loginURL, err := p.openid2Provider.openIDURL(waitId)
	if err != nil {
		return "", errgo.Mask(err)
	}
	u, err := parseQURL(loginURL)
	if err != nil {
		return "", errgo.Mask(err)
	}
	u.Query.Set("openid.lp.query_membership", openIdRequestedTeams)
	return u.String(), nil
}

// qURL holds a URL and its parsed query values.
type qURL struct {
	*url.URL
	Query url.Values
}

func parseQURL(s string) (*qURL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	qu := &qURL{
		URL: u,
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	qu.Query = q
	qu.URL.RawQuery = ""
	return qu, nil
}

func (qu *qURL) String() string {
	u := *qu.URL
	u.RawQuery = qu.Query.Encode()
	return u.String()
}

func (p *ussoProvider) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/callback", http.StripPrefix("/callback", p.openid2Provider.handler()))
	mux.Handle("/oauth", http.StripPrefix("/oauth", http.HandlerFunc(p.oauthLogin)))
	return mux
}

func (p *ussoProvider) oauthLogin(w http.ResponseWriter, r *http.Request) {
	reqURL := p.h.requestURL(r)
	id, err := verifyOAuthSignature(reqURL, r)
	if err != nil {
		p.h.loginFailure(w, r, err)
		return
	}
	db := p.h.store.DB.Copy()
	defer db.Close()
	var identity mongodoc.Identity
	if err := db.Identities().Find(bson.D{{"external_id", id}}).One(&identity); err != nil {
		p.h.loginFailure(w, r, errgo.Notef(err, "cannot get user details for %q", id))
		return
	}
	p.h.loginID(w, r, identity.Username)
}

var consumerKeyRegexp = regexp.MustCompile(`oauth_consumer_key="([^"]*)"`)

// verifyOAuthSignature verifies with Ubuntu SSO that the request is correctly
// signed.
func verifyOAuthSignature(requestURL string, req *http.Request) (string, error) {
	req.ParseForm()
	logger.Infof("RequestURL: %q", requestURL)
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
