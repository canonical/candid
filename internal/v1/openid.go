// Copyright 2015 Canonical Ltd.

package v1

import (
	"net/http"
	"strings"

	"github.com/kushaldas/openid.go/src/openid"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
)

type openid2Provider struct {
	claimedID      string
	location       string
	realm          string
	h              *Handler
	nonceStore     *openid.SimpleNonceStore
	discoveryCache *openid.SimpleDiscoveryCache
}

func newOpenID2Provider(h *Handler, location, claimedID, realm string) *openid2Provider {
	return &openid2Provider{
		claimedID: claimedID,
		location:  location,
		realm:     realm,
		h:         h,
		nonceStore: &openid.SimpleNonceStore{
			Store: make(map[string][]*openid.Nonce),
		},
		discoveryCache: &openid.SimpleDiscoveryCache{},
	}
}

func (p *openid2Provider) handler() http.Handler {
	return http.HandlerFunc(p.handleCallback)
}

func (p *openid2Provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	reqURL := p.h.requestURL(r)
	openIdInfo, err := openid.Verify(reqURL, p.discoveryCache, p.nonceStore)
	if err != nil {
		p.h.loginFailure(w, r, err)
		return
	}
	err = p.h.store.UpsertIdentity(&mongodoc.Identity{
		Username:   openIdInfo["nick"],
		ExternalID: openIdInfo["user"],
		Email:      openIdInfo["email"],
		FullName:   openIdInfo["fullname"],
		Groups:     strings.FieldsFunc(openIdInfo["teams"], isComma),
	})
	if err != nil {
		p.h.loginFailure(w, r, err)
		return
	}
	p.h.loginSuccess(w, r, openIdInfo["nick"])
}

func isComma(r rune) bool {
	return r == ','
}

func (p *openid2Provider) openIDURL(waitid string) (string, error) {
	callback := p.location
	if waitid != "" {
		callback += "?waitid=" + waitid
	}
	loginURL, err := openid.RedirectUrl(p.claimedID, callback, p.realm)
	if err != nil {
		return "", errgo.Mask(err)
	}
	return loginURL, nil
}
