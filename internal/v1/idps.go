// Copyright 2014 Canonical Ltd.

package v1

import (
	"encoding/json"
	"net/http"
	"strings"

	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

// serveIdentityProvider serves the /idps endpints. See http://tinyurl.com/oanmhy5 for
// details.
func (h *Handler) serveIdentityProviders(hdr http.Header, req *http.Request) (interface{}, error) {
	switch req.Method {
	case "GET":
		p := strings.TrimPrefix(req.URL.Path, "/")
		if p == "" {
			return h.store.IdentityProviderNames()
		}
		return h.getIdentityProvider(p)
	case "PUT":
		var idp params.IdentityProvider
		dec := json.NewDecoder(req.Body)
		err := dec.Decode(&idp)
		if err != nil {
			return nil, errgo.WithCausef(err, params.ErrBadRequest, `invalid identity provider`)
		}
		return h.setIdentityProvider(&idp)
	}
	return nil, errgo.WithCausef(nil, params.ErrBadRequest, `unsupported method "%s"`, req.Method)
}

// getIdentityProvider retrieves the identity provider information from
// the store and creates the response.
func (h *Handler) getIdentityProvider(p string) (*params.IdentityProvider, error) {
	doc, err := h.store.IdentityProvider(p)
	if err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return nil, errgo.WithCausef(nil, params.ErrNotFound, `cannot find identity provider "%v"`, p)
		}
		return nil, err
	}
	idp := params.IdentityProvider{
		Name:     doc.Name,
		Protocol: doc.Protocol,
		Settings: make(map[string]interface{}),
	}
	if doc.Protocol == params.ProtocolOpenID20 {
		idp.Settings[params.OpenID20LoginURL] = doc.LoginURL
		// TODO(mhilton) possibly add association id and return to address
		// depending on the workflow
	}
	return &idp, nil
}

// setIdentityProvider stores the identity provider in idp in the store.
func (h *Handler) setIdentityProvider(idp *params.IdentityProvider) (bool, error) {
	switch idp.Protocol {
	case params.ProtocolOpenID20:
		if idp.Name == "" {
			return false, errgo.WithCausef(nil, params.ErrBadRequest, "No name for identity provider")
		}
		var loginURL string
		if data, ok := idp.Settings[params.OpenID20LoginURL]; ok {
			loginURL, ok = data.(string)
		}
		if loginURL == "" {
			return false, errgo.WithCausef(nil, params.ErrBadRequest, "%s not specified", params.OpenID20LoginURL)
		}
		doc := &mongodoc.IdentityProvider{
			Name:     idp.Name,
			Protocol: idp.Protocol,
			LoginURL: loginURL,
		}
		if err := h.store.SetIdentityProvider(doc); err != nil {
			return false, errgo.Notef(err, "cannot set identity provider")
		}
		return true, nil
	default:
		return false, errgo.WithCausef(nil, params.ErrBadRequest, `unsupported identity protocol "%v"`, idp.Protocol)
	}
}
