// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"

	"github.com/kushaldas/openid.go/src/openid"
	"gopkg.in/errgo.v1"
)

type ussoProvider struct {
	nonceStore     *openid.SimpleNonceStore
	discoveryCache *openid.SimpleDiscoveryCache
}

const (
	ussoRealm    = "" // TODO Doesn't work if this is non-empty; why?
	ussoLoginURL = "https://login.ubuntu.com"
)

func newUSSOProvider() idProvider {
	return &ussoProvider{
		nonceStore: &openid.SimpleNonceStore{
			Store: make(map[string][]*openid.Nonce),
		},
		discoveryCache: &openid.SimpleDiscoveryCache{},
	}
}

// loginURL returns a URL that, when visited, will provide a login
// page and then redirect back to the USSO provider to complete
// the macaroon acquisition.
func (p *ussoProvider) loginURL(baseURL, waitId string) (string, error) {
	callback := baseURL + "?waitid=" + waitId
	return openid.RedirectUrl(ussoLoginURL, callback, ussoRealm)
}

// verifyCallback is invoked when we get a openid callback made
// by the openid login process. It returns any user
// info obtained from the request.
//
// It implements idProvider.verifyCallback
func (p *ussoProvider) verifyCallback(w http.ResponseWriter, req *http.Request) (*verifiedUserInfo, error) {
	reqURL := "http://" + req.Host + req.RequestURI

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
		Teams:    openIdInfo["teams"],
	}
	return info, nil
}
