// Copyright 2014 Canonical Ltd.

package v1

import (
	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/params"
)

type identityProvidersRequest struct {
	httprequest.Route `httprequest:"GET /idps"`
}

// serveIdentityProvider serves the /idps endpints. See http://tinyurl.com/oanmhy5 for
// details.
func (h *handler) ServeIdentityProviders(*identityProvidersRequest) (interface{}, error) {
	return h.store.IdentityProviderNames()
}

type identityProviderRequest struct {
	httprequest.Route `httprequest:"GET /idps/:idp"`
	Name              string `httprequest:"idp,path"`
}

func (h *handler) ServeIdentityProvider(p httprequest.Params, i *identityProviderRequest) (*params.IdentityProvider, error) {
	doc, err := h.store.IdentityProvider(i.Name)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
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

type setIdentityProviderRequest struct {
	httprequest.Route        `httprequest:"PUT /idps/:idp"`
	*params.IdentityProvider `httprequest:",body"`
	Name                     params.Username `httprequest:"idp,path"`
}

func (h *handler) ServePutIdentityProvider(p httprequest.Params, i *setIdentityProviderRequest) error {
	if err := h.checkAdmin(p.Request); err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	var doc mongodoc.IdentityProvider
	if i.Name == "" {
		return errgo.WithCausef(nil, params.ErrBadRequest, "no name for identity provider")
	}
	doc.Name = string(i.Name)
	switch i.Protocol {
	case params.ProtocolOpenID20:
		doc.Protocol = params.ProtocolOpenID20
		if err := openid2IdentityProvider(&doc, i.IdentityProvider); err != nil {
			return errgo.Mask(err, errgo.Is(params.ErrBadRequest))
		}
	default:
		return errgo.WithCausef(nil, params.ErrBadRequest, `unsupported identity protocol "%v"`, i.IdentityProvider.Protocol)
	}
	if err := h.store.SetIdentityProvider(&doc); err != nil {
		return errgo.Notef(err, "cannot set identity provider")
	}
	return nil
}

func openid2IdentityProvider(doc *mongodoc.IdentityProvider, idp *params.IdentityProvider) error {
	var loginURL string
	if data, ok := idp.Settings[params.OpenID20LoginURL]; ok {
		loginURL, ok = data.(string)
	}
	if loginURL == "" {
		return errgo.WithCausef(nil, params.ErrBadRequest, "%s not specified", params.OpenID20LoginURL)
	}
	doc.LoginURL = loginURL
	return nil
}
