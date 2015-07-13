// Copyright 2014 Canonical Ltd.

package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/juju/httprequest"
	"github.com/yohcop/openid-go"
	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2/bson"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

const (
	ussoURL = "https://login.ubuntu.com"
)

// TODO It should not be necessary to know all the possible
// groups in advance.
//
// This list needs to contain any private teams that the system needs to know about.
const openIdRequestedTeams = "blues-development,charm-beta"

func (h *dischargeHandler) ussoOAuthURL(waitid string) (string, error) {
	loginURL := h.serviceURL("/v1/idp/usso/oauth")
	if waitid != "" {
		loginURL += "?waitid=" + waitid
	}
	return loginURL, nil
}

func (h *dischargeHandler) ussoOpenIDURL(waitID string) (string, error) {
	realm := h.serviceURL("/v1/idp/usso/callback")
	callback := realm
	if waitID != "" {
		callback += "?waitid=" + waitID
	}
	u, err := openid.RedirectURL(ussoURL, callback, realm)
	if err != nil {
		return "", errgo.Mask(err)
	}
	ext := url.Values{}
	ext.Set("openid.ns.sreg", "http://openid.net/extensions/sreg/1.1")
	ext.Set("openid.sreg.required", "email,fullname,nickname")
	ext.Set("openid.ns.lp", "http://ns.launchpad.net/2007/openid-teams")
	ext.Set("openid.lp.query_membership", openIdRequestedTeams)
	return fmt.Sprintf("%s&%s", u, ext.Encode()), nil
}

// ussoCallbackRequest documents the /v1/idp/usso/callback endpoint. This
// is used by the UbuntuSSO login sequence to indicate it has completed.
// Client code should not need to use this type.
type ussoCallbackRequest struct {
	httprequest.Route `httprequest:"GET /v1/idp/usso/callback"`
	OPEndpoint        string `httprequest:"openid.op_endpoint,form"`
	ExternalID        string `httprequest:"openid.claimed_id,form"`
	Signed            string `httprequest:"openid.signed,form"`
	Email             string `httprequest:"openid.sreg.email,form"`
	Fullname          string `httprequest:"openid.sreg.fullname,form"`
	Nickname          string `httprequest:"openid.sreg.nickname,form"`
	Groups            string `httprequest:"openid.lp.is_member,form"`
}

func (h *dischargeHandler) USSOCallback(p httprequest.Params, r *ussoCallbackRequest) {
	_, err := openid.Verify(h.requestURL(), h.h.discoveryCache, h.h.nonceStore)
	if err != nil {
		h.loginFailure(p.Response, p.Request, r.Nickname, err)
		return
	}
	if r.OPEndpoint != ussoURL+"/+openid" {
		h.loginFailure(
			p.Response,
			p.Request,
			r.Nickname,
			errgo.WithCausef(nil, params.ErrForbidden, "rejecting login from %s", r.OPEndpoint),
		)
		return
	}
	signed := make(map[string]bool)
	for _, f := range strings.Split(r.Signed, ",") {
		signed[f] = true
	}
	if r.Email == "" || !signed["sreg.email"] {
		h.loginFailure(p.Response, p.Request, r.Nickname, errgo.New("sreg.email not specified"))
		return
	}
	if r.Fullname == "" || !signed["sreg.fullname"] {
		h.loginFailure(p.Response, p.Request, r.Nickname, errgo.New("sreg.fullname not specified"))
		return
	}
	if r.Nickname == "" || !signed["sreg.nickname"] {
		h.loginFailure(p.Response, p.Request, r.Nickname, errgo.New("sreg.nickname not specified"))
		return
	}
	var groups []string
	if r.Groups != "" && signed["lp.is_member"] {
		groups = strings.Split(r.Groups, ",")
	}
	err = h.store.UpsertIdentity(&mongodoc.Identity{
		Username:   r.Nickname,
		ExternalID: r.ExternalID,
		Email:      r.Email,
		FullName:   r.Fullname,
		Groups:     groups,
	})
	if err != nil {
		h.loginFailure(p.Response, p.Request, r.Nickname, err)
		return
	}
	h.loginID(p.Response, p.Request, r.Nickname)
}

// ussoOAuthRequest is a request to log in using oauth tokens. A request
// to the /v1/idp/usso/oauth endpoint should be signed using a previously
// aquired OAuth token.
type ussoOAuthRequest struct {
	httprequest.Route `httprequest:"GET /v1/idp/usso/oauth"`
	WaitID            string `httprequest:"waitid,form"`
}

func (h *dischargeHandler) USSOOAuthLogin(p httprequest.Params, _ *ussoOAuthRequest) {
	reqURL := h.requestURL()
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
