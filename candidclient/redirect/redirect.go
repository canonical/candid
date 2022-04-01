// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

// Package redirect implements redirection based login.
package redirect

import (
	"context"
	"net/url"
	"strings"

	errgo "gopkg.in/errgo.v1"
	httprequest "gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v3/httpbakery"

	"github.com/canonical/candid/params"
)

const Kind = "browser-redirect"

type InteractionInfo struct {
	// LoginURL contains the URL to redirect to in order to start a
	// login attempt.
	LoginURL string

	// DischargeTokenURL contains the URL that is used to swap a
	// login code for a discharge token.
	DischargeTokenURL string
}

// RedirectURL calculates the URL to redirect to in order to initate a
// browser-redirect login.
func (i InteractionInfo) RedirectURL(returnTo, state string) string {
	v := make(url.Values, 2)
	v.Set("return_to", returnTo)
	v.Set("state", state)

	var sb strings.Builder
	sb.WriteString(i.LoginURL)
	if strings.Contains(i.LoginURL, "?") {
		sb.WriteByte('&')
	} else {
		sb.WriteByte('?')
	}
	sb.WriteString(v.Encode())
	return sb.String()
}

// SetInteraction adds interaction info the the browser-redirect interaction type.
func SetInteraction(ierr *httpbakery.Error, loginURL, dischargeTokenURL string) {
	ierr.SetInteraction(Kind, InteractionInfo{
		LoginURL:          loginURL,
		DischargeTokenURL: dischargeTokenURL,
	})
}

// DischargeTokenRequest represents a request to the DischargeTokenURL.
type DischargeTokenRequest struct {
	httprequest.Route `httprequest:"POST"`
	Body              struct {
		Code string `json:"code"`
	} `httprequest:",body"`
}

// DischargeTokenResponse contains a response from a DischargeTokenURL.
type DischargeTokenResponse struct {
	DischargeToken *httpbakery.DischargeToken `json:"token,omitempty"`
}

// GetDischargeToken retrieves the discharge token associated with the
// given code.
func (i InteractionInfo) GetDischargeToken(ctx context.Context, code string) (*httpbakery.DischargeToken, error) {
	client := new(httprequest.Client)
	var req DischargeTokenRequest
	req.Body.Code = code

	var resp DischargeTokenResponse
	if err := client.CallURL(ctx, i.DischargeTokenURL, &req, &resp); err != nil {
		return nil, errgo.Mask(err)
	}
	return resp.DischargeToken, nil
}

// ParseLoginResult extracts the result from a response callback.
func ParseLoginResult(requestURL string) (state, code string, err error) {
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", "", errgo.Mask(err)
	}
	v := u.Query()
	if e := v.Get("error"); e != "" {
		if ec := v.Get("error_code"); ec != "" {
			return v.Get("state"), "", errgo.WithCausef(nil, params.ErrorCode(ec), "%s", e)
		}
		return v.Get("state"), "", errgo.Newf("%s", e)
	}
	return v.Get("state"), v.Get("code"), nil
}

type Interactor struct {
	dischargeTokens map[string]httpbakery.DischargeToken
}

// Kind implements httpbakery.Interactor.
func (*Interactor) Kind() string {
	return Kind
}

// Interact implements httpbakery.Interactor.
func (i *Interactor) Interact(ctx context.Context, _ *httpbakery.Client, _ string, ierr *httpbakery.Error) (*httpbakery.DischargeToken, error) {
	var v InteractionInfo
	if err := ierr.InteractionMethod(Kind, &v); err != nil {
		return nil, errgo.Mask(err, errgo.Is(httpbakery.ErrInteractionMethodNotFound))
	}
	if dt, ok := i.dischargeTokens[v.LoginURL]; ok {
		return &dt, nil
	}
	return nil, &httpbakery.InteractionError{
		Reason: &RedirectRequiredError{
			InteractionInfo: v,
		},
	}
}

// SetDischargeToken sets a discharge token for a particular login URL.
func (i *Interactor) SetDischargeToken(loginURL string, dt *httpbakery.DischargeToken) {
	if i.dischargeTokens == nil {
		i.dischargeTokens = make(map[string]httpbakery.DischargeToken)
	}
	if dt == nil {
		delete(i.dischargeTokens, loginURL)
	} else {
		i.dischargeTokens[loginURL] = *dt
	}
}

// A RedirectRequiredError is the type of error returned from an
// interactor when an interaction via redirection is required.
type RedirectRequiredError struct {
	InteractionInfo InteractionInfo
}

// Error implements error.
func (e RedirectRequiredError) Error() string {
	return "redirect required"
}

// IsRedirectRequiredError determines if an error is a
// RedirectRequiredError.
func IsRedirectRequiredError(err error) bool {
	_, ok := err.(*RedirectRequiredError)
	return ok
}
