// Copyright 2015 Canonical Ltd.

package v1

import (
	"strings"

	"github.com/juju/httprequest"
	"github.com/kushaldas/openid.go/src/openid"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
)

func (h *dischargeHandler) openIDURL(path, waitid, claimedID, realm string) (string, error) {
	callback := h.serviceURL(path)
	if waitid != "" {
		callback += "?waitid=" + waitid
	}
	loginURL, err := openid.RedirectUrl(claimedID, callback, realm)
	if err != nil {
		return "", errgo.Mask(err)
	}
	return loginURL, nil
}

func (h *dischargeHandler) handleOpenIDCallback(p httprequest.Params) {
	reqURL := h.requestURL()
	openIdInfo, err := openid.Verify(reqURL, h.h.discoveryCache, h.h.nonceStore)
	if err != nil {
		h.loginFailure(p.Response, p.Request, "", err)
		return
	}
	err = h.store.UpsertIdentity(&mongodoc.Identity{
		Username:   openIdInfo["nick"],
		ExternalID: openIdInfo["user"],
		Email:      openIdInfo["email"],
		FullName:   openIdInfo["fullname"],
		Groups:     strings.FieldsFunc(openIdInfo["teams"], isComma),
	})
	if err != nil {
		h.loginFailure(p.Response, p.Request, openIdInfo["nick"], err)
		return
	}
	h.loginID(p.Response, p.Request, openIdInfo["nick"])
}

func isComma(r rune) bool {
	return r == ','
}
