// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

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

	"github.com/juju/loggo"
	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/CanonicalLtd/candidclient.v1/ussodischarge"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/CanonicalLtd/candid/config"
	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/idputil"
	"github.com/CanonicalLtd/candid/store"
)

var logger = loggo.GetLogger("candid.idp.usso.ussodischarge")

const (
	operationName        = "usso-discharge-login"
	timeFormat           = "2006-01-02T15:04:05.000000"
	ussoMacaroonDuration = 100 * 365 * 24 * time.Hour
)

var ussoLoginOp = bakery.Op{
	Entity: "ussologin",
	Action: "login",
}

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
	hostname    string
	params      Params
	initParams  idp.InitParams
	ussoChecker *ussoCaveatChecker
	checker     *identchecker.Checker
}

// Name gives the name of the identity provider (usso).
func (*identityProvider) Name() string {
	return "usso_macaroon"
}

// Domain implements idp.IdentityProvider.Domain
func (idp *identityProvider) Domain() string {
	return idp.params.Domain
}

// Description gives a description of the identity provider.
func (*identityProvider) Description() string {
	return "Ubuntu SSO macaroon discharge authentication"
}

// Interactive specifies that this identity provider is not interactive.
func (*identityProvider) Interactive() bool {
	return false
}

// Init initialises the identity provider.
func (idp *identityProvider) Init(_ context.Context, params idp.InitParams) error {
	idp.initParams = params
	idp.ussoChecker = &ussoCaveatChecker{
		fallback:  httpbakery.NewChecker(),
		namespace: idp.hostname,
	}
	idp.checker = identchecker.NewChecker(identchecker.CheckerParams{
		Checker:          idp.ussoChecker,
		MacaroonVerifier: params.Oven,
	})
	return nil
}

// URL gets the login URL to use this identity provider.
func (idp *identityProvider) URL(dischargeID string) string {
	return idputil.URL(idp.initParams.URLPrefix, "/login", dischargeID)
}

func (idp *identityProvider) SetInteraction(ierr *httpbakery.Error, dischargeID string) {
	ussodischarge.SetInteraction(ierr, idputil.URL(idp.initParams.URLPrefix, "/interact", dischargeID))
}

//  GetGroups implements idp.IdentityProvider.GetGroups.
func (*identityProvider) GetGroups(context.Context, *store.Identity) ([]string, error) {
	return nil, nil
}

// Handle handles the Ubuntu SSO Macaroon login process.
func (idp *identityProvider) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	switch strings.TrimPrefix(req.URL.Path, idp.initParams.URLPrefix) {
	case "/login":
		if err := idp.handleLogin(ctx, w, req); err != nil {
			idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
		}
	case "/interact":
		if err := idp.handleInteract(ctx, w, req); err != nil {
			idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), err)
		}
	default:
		idp.initParams.VisitCompleter.Failure(ctx, w, req, idputil.DischargeID(req), errgo.WithCausef(nil, params.ErrNotFound, "path %q not found", req.URL.Path))
	}

}

func (idp identityProvider) handleLogin(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	switch req.Method {
	case "GET":
		m, err := idp.ussoMacaroon(ctx)
		if err != nil {
			return err
		}
		httprequest.WriteJSON(w, http.StatusOK, ussodischarge.MacaroonResponse{
			Macaroon: m,
		})
	case "POST":
		user, err := idp.verifyUSSOMacaroon(ctx, req)
		if err != nil {
			return err
		}
		err = idp.initParams.Store.UpdateIdentity(
			ctx,
			user,
			store.Update{
				store.Username: store.Set,
				store.Name:     store.Set,
				store.Email:    store.Set,
			},
		)
		if err != nil {
			return err
		}
		idp.initParams.VisitCompleter.Success(ctx, w, req, idputil.DischargeID(req), user)
	default:
		return errgo.WithCausef(nil, params.ErrBadRequest, "unexpected method %q", req.Method)
	}
	return nil
}

func (idp identityProvider) handleInteract(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	switch req.Method {
	case "GET":
		m, err := idp.ussoMacaroon(ctx)
		if err != nil {
			return err
		}
		httprequest.WriteJSON(w, http.StatusOK, ussodischarge.MacaroonResponse{
			Macaroon: m,
		})
	case "POST":
		user, err := idp.verifyUSSOMacaroon(ctx, req)
		if err != nil {
			return err
		}
		err = idp.initParams.Store.UpdateIdentity(
			ctx,
			user,
			store.Update{
				store.Username: store.Set,
				store.Name:     store.Set,
				store.Email:    store.Set,
			},
		)
		if err != nil {
			return err
		}
		token, err := idp.initParams.DischargeTokenCreator.DischargeToken(ctx, user)
		if err != nil {
			return err
		}
		httprequest.WriteJSON(w, http.StatusOK, ussodischarge.LoginResponse{
			DischargeToken: token,
		})
	default:
		return errgo.WithCausef(nil, params.ErrBadRequest, "unexpected method %q", req.Method)
	}
	return nil
}

func (idp *identityProvider) ussoMacaroon(ctx context.Context) (*bakery.Macaroon, error) {
	fail := func(err error) (*bakery.Macaroon, error) {
		return nil, err
	}
	// Mint a macaroon that's only good for USSO discharge and can't
	// used for normal login.
	m, err := idp.initParams.Oven.NewMacaroon(
		ctx,
		bakery.Version1,
		[]checkers.Caveat{checkers.TimeBeforeCaveat(time.Now().Add(ussoMacaroonDuration))},
		ussoLoginOp,
	)
	if err != nil {
		return fail(errgo.Mask(err))
	}
	rootKey, caveatID, err := idp.ussoThirdPartyCaveat()
	if err != nil {
		return fail(errgo.Notef(err, "cannot create third-party caveat"))
	}
	// We need to add the third party caveat directly to the underlying
	// macaroon as it's encoded differently from the bakery convention.
	if err := m.M().AddThirdPartyCaveat(rootKey, caveatID, idp.params.URL); err != nil {
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

func (idp *identityProvider) verifyUSSOMacaroon(ctx context.Context, req *http.Request) (*store.Identity, error) {
	var lr ussodischarge.LoginRequest
	if err := httprequest.Unmarshal(idputil.RequestParams(ctx, nil, req), &lr); err != nil {
		return nil, errgo.Mask(err)
	}
	_, err := idp.checker.Auth(lr.Login.Macaroons).Allow(ctx, ussoLoginOp)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrBadRequest))
	}
	var acct accountInfo
	if idp.ussoChecker.accountInfo == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "account information not specified")
	}
	buf, err := base64.StdEncoding.DecodeString(idp.ussoChecker.accountInfo)
	if err != nil {
		return nil, ussoCaveatErrorf("account caveat badly formed: %v", err)
	}
	if err := json.Unmarshal(buf, &acct); err != nil {
		return nil, ussoCaveatErrorf("account caveat badly formed: %v", err)
	}
	if acct.OpenID == "" {
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "account information not specified")
	}
	return &store.Identity{
		ProviderID: store.MakeProviderIdentity("usso_macaroon", acct.OpenID),
		Username:   acct.OpenID + "@" + idp.params.Domain,
		Name:       acct.DisplayName,
		Email:      acct.Email,
	}, nil
}

type ussoCaveatChecker struct {
	namespace   string
	fallback    bakery.FirstPartyCaveatChecker
	accountInfo string
}

func (c *ussoCaveatChecker) Namespace() *checkers.Namespace {
	return nil
}

// CheckFirstPartyCaveat checks the first party caveats that are added by the
// USSO discharger.
func (c *ussoCaveatChecker) CheckFirstPartyCaveat(ctx context.Context, caveat string) error {
	i1 := strings.Index(caveat, "|")
	if i1 == -1 || caveat[0:i1] != c.namespace {
		return c.fallback.CheckFirstPartyCaveat(ctx, caveat)
	}
	i2 := strings.Index(caveat[i1+1:], "|")
	if i2 == -1 {
		return errgo.WithCausef(nil, checkers.ErrCaveatNotRecognized, "verification failed (USSO caveat): no argument provided in %q", caveat)
	}
	i2 += i1 + 1
	cond, arg := caveat[i1+1:i2], caveat[i2+1:]
	switch cond {
	case "account":
		if c.accountInfo != "" && c.accountInfo != arg {
			return ussoCaveatErrorf("account specified inconsistently")
		}
		c.accountInfo = arg
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
			return ussoCaveatErrorf("expires caveat badly formed: %v", err)
		}
		if time.Now().After(t) {
			return ussoCaveatErrorf("expires before current time")
		}
		return nil
	default:
		return errgo.WithCausef(nil, checkers.ErrCaveatNotRecognized, "verification failed (USSO caveat): unknown caveat %q", cond)
	}
}

func ussoCaveatErrorf(f string, a ...interface{}) error {
	return errgo.Newf("verification failed (USSO caveat): %s", fmt.Sprintf(f, a...))
}

type accountInfo struct {
	OpenID      string `json:"openid"`
	Email       string `json:"email"`
	DisplayName string `json:"displayname"`
	Username    string `json:"username"`
	IsVerified  bool   `json:"is_verified"`
}
