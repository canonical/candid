// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/kushaldas/openid.go/src/openid"
	"gopkg.in/errgo.v1"
)

type ussoProvider struct {
	baseURL        string
	nonceStore     *openid.SimpleNonceStore
	discoveryCache *openid.SimpleDiscoveryCache
}

const (
	ussoRealm    = "" // TODO Doesn't work if this is non-empty; why?
	ussoLoginURL = "https://login.ubuntu.com"
)

func newUSSOProvider(baseURL string) idProvider {
	return &ussoProvider{
		baseURL: baseURL,
		nonceStore: &openid.SimpleNonceStore{
			Store: make(map[string][]*openid.Nonce),
		},
		discoveryCache: &openid.SimpleDiscoveryCache{},
	}
}

// TODO It should not be necessary to know all the possible
// groups in advance.
const openIdRequestedTeams = "yellow,blues-development,charm-beta"

// openidRedirectURL is defined as a variable so that it
// can be replaced for testing purposes.
var openidRedirectURL = openid.RedirectUrl

// loginURL returns a URL that, when visited, will provide a login
// page and then redirect back to the USSO provider to complete
// the macaroon acquisition.
func (p *ussoProvider) loginURL(baseURL, waitId string) (string, error) {
	callback := baseURL + "?waitid=" + waitId
	redirectURL, err := openid.RedirectUrl(ussoLoginURL, callback, ussoRealm)
	if err != nil {
		return "", errgo.Mask(err)
	}
	u, err := parseQURL(redirectURL)
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

// verifyCallback is invoked when we get a openid callback made
// by the openid login process. It returns any user
// info obtained from the request.
//
// It implements idProvider.verifyCallback
func (p *ussoProvider) verifyCallback(w http.ResponseWriter, req *http.Request) (*verifiedUserInfo, error) {
	reqURL := p.baseURL + req.RequestURI

	// TODO the RequestURI may not be the same as in the original
	// callback URL because of frontend processing. We could
	// fix up the URL passed to Verify so that it is correct regardless,
	// as it probably doesn't actually matter for our purposes.
	openIdInfo, err := openid.Verify(reqURL, p.discoveryCache, p.nonceStore)
	if err != nil {
		return nil, errgo.Notef(err, "openID verification failed")
	}
	// the openid package should really return this stuff as a struct...
	info := &verifiedUserInfo{
		User:     openIdInfo["user"],
		Nickname: openIdInfo["nick"],
		FullName: openIdInfo["fullname"],
		Email:    openIdInfo["email"],
		Groups:   strings.FieldsFunc(openIdInfo["teams"], isComma),
	}
	return info, nil
}

func isComma(r rune) bool {
	return r == ','
}
