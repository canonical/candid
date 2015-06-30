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
	"github.com/juju/httprequest"
)

const (
	ussoURL   = "https://login.ubuntu.com"
)

// TODO It should not be necessary to know all the possible
// groups in advance.
//
// This list needs to contain any private teams that the system needs to know about.
const openIdRequestedTeams = "blues-development,charm-beta"

func (h *handler) ussoOAuthURL(waitid string) (string, error) {
	loginURL := h.location + "/v1/idp/usso/oauth"
	if waitid != "" {
		loginURL += "?waitid=" + waitid
	}
	return loginURL, nil
}

func (h *handler) ussoOpenIDURL(waitID string) (string, error) {
	realmURL := h.location + "/v1/idp/usso/callback"
	loginURL, err := h.openIDURL("/v1/idp/usso/callback", waitID, ussoURL, realmURL)
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

type ussoCallbackRequest struct {
	httprequest.Route `httprequest:"GET /idp/usso/callback"`
}

func (h *handler) ServeUSSOCallback(p httprequest.Params, _ *ussoCallbackRequest) {
	h.handleOpenIDCallback(p)
}

type ussoOAuthRequest struct {
	httprequest.Route `httprequest:"GET /idp/usso/oauth"`
	WaitID            string `httprequest:"waitid,form"`
}

func (h *handler) ServeOAuthLogin(p httprequest.Params, r *ussoOAuthRequest) {
	reqURL := h.requestURL(p.Request)
	id, err := verifyOAuthSignature(reqURL, p.Request)
	if err != nil {
		h.loginFailure(p.Response, p.Request, "unknown user", err)
		return
	}
	var identity mongodoc.Identity
	if err := h.store.DB.Identities().Find(bson.D{{"external_id", id}}).One(&identity); err != nil {
		h.loginFailure(p.Response, p.Request, id, errgo.Notef(err, "cannot get user details for %q", id))
		return
	}
	h.loginID(p.Response, p.Request, identity.Username)
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
