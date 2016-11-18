// Copyright 2016 Canonical Ltd.

// Pacakge ussodischarge is an identity provider that authenticates against
// Ubuntu SSO using Ubuntu SSO's macaroon protocol.
package ussodischarge

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/juju/idmclient/ussodischarge"
	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon.v2-unstable"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/idputil"
)

var logger = loggo.GetLogger("identity.idp.usso.ussodischarge")

const (
	operationName = "usso-discharge-login"
	timeFormat    = "2006-01-02T15:04:05.000000"
)

func init() {
	config.RegisterIDP("usso_macaroon", func(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
		var p Params
		if err := unmarshal(&p); err != nil {
			return nil, err
		}
		return NewIdentityProvider(p)
	})
}

// Params holds the parameters to use with UbuntuSSO macaroon identity
// providers.
type Params struct {
	// Domain will be appended to any usernames or groups provided by
	// the identity provider. A user created by this identity provide
	// will be openid@domain.
	Domain string `yaml:"domain"`

	// URL is the address of the Ubuntu SSO server.
	URL string `yaml:"url"`

	// PublicKey is the RSA public key used to encrypt caveats for
	// UbuntuSSO third party caveats.
	PublicKey PublicKey `yaml:"public-key"`
}

// PublicKey is a PublicKey parameter for
type PublicKey struct {
	rsa.PublicKey
}

// UnmarshalText implements encoding.TextUnmarshaler by
// unmarshaling the PEM-encoded RSA public key from text.
func (k *PublicKey) UnmarshalText(text []byte) error {
	block, _ := pem.Decode(text)
	if block.Type != "PUBLIC KEY" {
		return errgo.Newf("value is not a PUBLIC KEY")
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errgo.Notef(err, "cannot parse public key")
	}
	rsapk, ok := pk.(*rsa.PublicKey)
	if !ok {
		return errgo.Newf("unsupported public key type %T", pk)
	}
	k.PublicKey = *rsapk
	return nil
}

// NewIdentityProvider creates an idp.IdentityProvider that uses Ubuntu
// SSO macaroon authentication, with the configuration defined by p.
func NewIdentityProvider(p Params) (idp.IdentityProvider, error) {
	if p.Domain == "" {
		return nil, errgo.New(`required parameter "domain" not specified`)
	}
	if p.URL == "" {
		return nil, errgo.New(`required parameter "url" not specified`)
	}
	u, err := url.Parse(p.URL)
	if err != nil {
		return nil, errgo.Notef(err, `cannot parse "url"`)
	}
	return &identityProvider{
		hostname: u.Host,
		params:   p,
	}, nil
}

// identityProvider is an identity provider that authenticates to Ubuntu
// SSO by requiring the client to discharge a macaroon addressed directly
// to UbuntuSSO.
type identityProvider struct {
	hostname string
	params   Params
}

// Name gives the name of the identity provider (usso).
func (idp identityProvider) Name() string {
	return "usso_macaroon"
}

// Description gives a description of the identity provider.
func (identityProvider) Description() string {
	return "Ubuntu SSO macaroon discharge authentication"
}

// Interactive specifies that this identity provider is not interactive.
func (identityProvider) Interactive() bool {
	return false
}

// URL gets the login URL to use this identity provider.
func (identityProvider) URL(c idp.URLContext, waitID string) (string, error) {
	url := c.URL("/login")
	if waitID != "" {
		url += "?waitid=" + waitID
	}
	return url, nil
}

// Handle handles the Ubuntu SSO Macaroon login process.
func (idp identityProvider) Handle(c idp.Context) {
	if err := idp.handle(c); err != nil {
		c.LoginFailure(err)
	}
}

func (idp identityProvider) handle(c idp.Context) error {
	p := c.Params()
	switch p.Request.Method {
	case "GET":
		m, err := idp.ussoMacaroon(c.Bakery())
		if err != nil {
			return err
		}
		httprequest.WriteJSON(p.Response, http.StatusOK, ussodischarge.MacaroonResponse{
			Macaroon: m,
		})
	case "POST":
		user, err := idp.verifyUSSOMacaroon(c.Bakery(), p)
		if err != nil {
			return err
		}
		err = c.UpdateUser(user)
		if err != nil {
			return err
		}
		idputil.LoginUser(c, user)
	default:
		return errgo.WithCausef(nil, params.ErrBadRequest, "unexpected method %q", p.Request.Method)
	}
	return nil
}

func (idp identityProvider) ussoMacaroon(bs *bakery.Service) (*macaroon.Macaroon, error) {
	fail := func(err error) (*macaroon.Macaroon, error) {
		return nil, err
	}
	// Mint a macaroon that's only good for USSO discharge and can't
	// used for normal login.
	m, err := bs.NewMacaroon(bakery.Version1, []checkers.Caveat{
		checkers.AllowCaveat(operationName),
	})
	if err != nil {
		return fail(errgo.Mask(err))
	}
	rootKey, caveatID, err := idp.ussoThirdPartyCaveat()
	if err != nil {
		return fail(errgo.Notef(err, "cannot create third-party caveat"))
	}
	if err := m.AddThirdPartyCaveat(rootKey, caveatID, idp.params.URL); err != nil {
		return fail(errgo.Notef(err, "cannot create macaroon"))
	}
	return m, nil
}

func (idp identityProvider) ussoThirdPartyCaveat() (rootKey, caveatID []byte, err error) {
	fail := func(err error) ([]byte, []byte, error) {
		return nil, nil, err
	}
	rootKey = make([]byte, 24)
	if _, err = rand.Read(rootKey); err != nil {
		return fail(errgo.Mask(err))
	}
	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &idp.params.PublicKey.PublicKey, rootKey[:], nil)
	if err != nil {
		return fail(errgo.Mask(err))
	}
	cid := ussoCaveatID{
		Secret:  base64.StdEncoding.EncodeToString(encryptedKey),
		Version: 1,
	}
	caveatID, err = json.Marshal(cid)
	if err != nil {
		return fail(errgo.Mask(err))
	}
	return rootKey, caveatID, nil
}

// ussoCaveatID is a third-party caveat ID that is understood by Ubuntu
// SSO.
type ussoCaveatID struct {
	Secret  string `json:"secret"`
	Version int    `json:"version"`
}

func (idp identityProvider) verifyUSSOMacaroon(bs *bakery.Service, p httprequest.Params) (*params.User, error) {
	var req ussodischarge.LoginRequest
	if err := httprequest.Unmarshal(p, &req); err != nil {
		return nil, errgo.Mask(err)
	}
	checker := &ussoCaveatChecker{
		checker: checkers.New(
			checkers.OperationChecker(operationName),
		),
		namespace: idp.hostname,
	}
	if err := bs.Check(req.Login.Macaroons, checker); err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrBadRequest))
	}
	if checker.accountInfo == nil || checker.accountInfo.OpenID == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "account information not specified")
	}
	return &params.User{
		Username:   params.Username(checker.accountInfo.OpenID + "@" + idp.params.Domain),
		ExternalID: fmt.Sprintf("%s-openid:%s", idp.params.Domain, checker.accountInfo.OpenID),
		FullName:   checker.accountInfo.DisplayName,
		Email:      checker.accountInfo.Email,
	}, nil
}

type ussoCaveatChecker struct {
	checker         bakery.FirstPartyChecker
	namespace       string
	haveAccountInfo bool
	accountInfo     *accountInfo
}

// CheckFirstPartyCaveat checks the first party caveats that are added by the
// USSO discharger.
func (c *ussoCaveatChecker) CheckFirstPartyCaveat(caveat string) error {
	condArg := strings.TrimPrefix(caveat, c.namespace+"|")
	if condArg == caveat {
		if c.checker == nil {
			return errgo.WithCausef(nil, checkers.ErrCaveatNotRecognized, "unknown caveat %q", caveat)
		}
		return c.checker.CheckFirstPartyCaveat(caveat)
	}
	i := strings.Index(condArg, "|")
	if i < 0 {
		return errgo.WithCausef(nil, checkers.ErrCaveatNotRecognized, "unknown caveat %q", caveat)
	}
	cond, arg := condArg[:i], condArg[i+1:]
	switch cond {
	case "account":
		if c.accountInfo != nil {
			return errgo.WithCausef(nil, params.ErrBadRequest, "%s|account specified multiple times", c.namespace)
		}
		buf, err := base64.StdEncoding.DecodeString(arg)
		if err != nil {
			return errgo.WithCausef(err, params.ErrBadRequest, "%s|account caveat badly formed", c.namespace)
		}
		if err := json.Unmarshal(buf, &c.accountInfo); err != nil {
			return errgo.WithCausef(err, params.ErrBadRequest, "%s|account caveat badly formed", c.namespace)
		}
		return nil
	case "valid_since":
		// We don't check the valid_since value to prevent
		// problems with slight clock skew between services.
		return nil
	case "last_auth":
		// TODO(mhilton) work out if there is anything we should
		// check with this.
		return nil
	case "expires":
		t, err := time.Parse(timeFormat, arg)
		if err != nil {
			return errgo.WithCausef(err, params.ErrBadRequest, "%s|expires caveat badly formed", c.namespace)
		}
		if time.Now().After(t) {
			return errgo.Newf("%s|expires before current time", c.namespace)
		}
		return nil
	default:
		return errgo.WithCausef(nil, checkers.ErrCaveatNotRecognized, "unknown caveat %q (%s)", caveat, cond)
	}
}

type accountInfo struct {
	OpenID      string `json:"openid"`
	Email       string `json:"email"`
	DisplayName string `json:"displayname"`
	Username    string `json:"username"`
	IsVerified  bool   `json:"is_verified"`
}
