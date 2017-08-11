// Copyright 2016 Canonical Ltd.

package debug

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/juju/idmclient/params"
	"github.com/juju/usso"
	"github.com/juju/usso/openid"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/nacl/box"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"

	"github.com/CanonicalLtd/blues-identity/internal/identity"
)

const cookieName = "debug-login"

// loginRequiredError is an error that indicates that a login request
// should be attempted.
type loginRequiredError struct {
	redirectURL string
}

func (*loginRequiredError) ErrorCode() params.ErrorCode {
	return identity.ErrLoginRequired
}

// Error implements error.Error.
func (err *loginRequiredError) Error() string {
	return fmt.Sprintf("login required to %q", err.redirectURL)
}

// SetHeader implements httprequest.HeaderSetter.
func (err *loginRequiredError) SetHeader(h http.Header) {
	h.Set("Location", err.redirectURL)
}

// cookie contains the data stored in the debug login cookie.
type cookie struct {
	// ExpireTime contains the time after which the cookie is
	// invalid.
	ExpireTime time.Time

	// ID contains the Ubuntu SSO ID of the user.
	ID string

	// Teams contains the subset of params.DebugTeams of which the
	// user is a member.
	Teams []string
}

func encodeCookie(k *bakery.KeyPair, c *cookie) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", errgo.Mask(err)
	}
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		return "", errgo.Mask(err)
	}
	edata := nonce[:]
	edata = box.Seal(edata, data, &nonce, (*[bakery.KeyLen]byte)(&k.Public.Key), (*[bakery.KeyLen]byte)(&k.Private.Key))
	return base64.StdEncoding.EncodeToString(edata), nil
}

func decodeCookie(k *bakery.KeyPair, v string) (*cookie, error) {
	edata, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, errgo.Notef(err, "cannot decode cookie")
	}
	var nonce [24]byte
	n := copy(nonce[:], edata)
	edata = edata[n:]
	data, ok := box.Open(nil, edata, &nonce, (*[bakery.KeyLen]byte)(&k.Public.Key), (*[bakery.KeyLen]byte)(&k.Private.Key))
	if !ok {
		return nil, errgo.New("cannot decrypt cookie")
	}
	var cookie cookie
	if err := json.Unmarshal(data, &cookie); err != nil {
		return nil, errgo.Notef(err, "cannot unmarshal cookie")
	}
	return &cookie, nil
}

// checkLogin checks that the given request contains a valid login cookie
// for accessing /debug endpoints. If there is any sort of error decoding
// the cookie the returned error will have a cause of type
// *loginRequiredError.
func (h *debugAPIHandler) checkLogin(r *http.Request) error {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return errgo.WithCausef(err, h.loginRequired(r), "no cookie")
	}
	cookie, err := decodeCookie(h.key, c.Value)
	if err != nil {
		return errgo.WithCausef(nil, h.loginRequired(r), "%s", err.Error())
	}
	if cookie.ExpireTime.Before(time.Now()) {
		return errgo.WithCausef(nil, h.loginRequired(r), "cookie expired")
	}
	for _, t1 := range cookie.Teams {
		for _, t2 := range h.teams {
			if t1 == t2 {
				return nil
			}
		}
	}
	return errgo.WithCausef(nil, h.loginRequired(r), "no suitable team membership")
}

// ussoClient is the client for the Ubuntu SSO server.
var ussoClient = openid.NewClient(usso.ProductionUbuntuSSOServer, nil, nil)

// loginRequired creates a new loginRequiredError for the given request.
func (h *debugAPIHandler) loginRequired(r *http.Request) *loginRequiredError {
	return &loginRequiredError{
		redirectURL: ussoClient.RedirectURL(&openid.Request{
			ReturnTo: h.location + "/debug/login?return_to=" + url.QueryEscape(h.location+r.URL.String()),
			Realm:    h.location + "/debug",
			Teams:    h.teams,
		}),
	}
}

// login handles callbacks from an Ubuntu SSO login attempt.
func (h *debugAPIHandler) login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	url := h.location + r.URL.String()
	resp, err := ussoClient.Verify(url)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "unauthorized: %s\n", err)
		return
	}
	for _, t1 := range resp.Teams {
		for _, t2 := range h.teams {
			if t1 == t2 {
				h.loginSuccess(w, r, resp)
				return
			}
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, "unauthorized: access denied for %s", resp.ID)
}

// loginSuccess completes a login when it has been deemed successful.
func (h *debugAPIHandler) loginSuccess(w http.ResponseWriter, r *http.Request, resp *openid.Response) {
	c := &cookie{
		ExpireTime: time.Now().Add(1 * time.Hour),
		ID:         resp.ID,
		Teams:      resp.Teams,
	}
	value, err := encodeCookie(h.key, c)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "cannot create cookie: %s", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    cookieName,
		Value:   value,
		Path:    "/debug",
		Expires: c.ExpireTime,
	})
	r.ParseForm()
	w.Header().Set("Location", r.Form.Get("return_to"))
	w.WriteHeader(http.StatusSeeOther)
}
