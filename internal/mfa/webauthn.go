// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package mfa contains implementation of a handler for multi-factor
// authentication with WebAuthn.
package mfa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/juju/loggo"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"

	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/idp/idputil"
	"github.com/canonical/candid/params"
	"github.com/canonical/candid/store"
)

var (
	logger                = loggo.GetLogger("candid.internal.mfa")
	errNoValidCredentials = errgo.New("no valid credentials")
)

// CookieName holds the name of the multi-factor authentication
// cookie.
const CookieName = "candid-login-mfa"

// CookiePath is the path to associate with the cookie storing the
// current multi-factor authentication state.
const CookiePath = "/login/mfa"

// StateName holds the name of the form field containing the multi-factor
// authentication state.
const StateName = "mfa-state"

type webauthnUser struct {
	*store.Identity
	Credentials []store.MFACredential
}

// WebAuthnID implements the webauthn.User interface.
func (u *webauthnUser) WebAuthnID() []byte {
	return []byte(u.Identity.ProviderID)
}

// WebAuthnName implements the webauthn.User interface.
func (u *webauthnUser) WebAuthnName() string {
	return u.Identity.Username
}

// WebAuthnDisplayName implements the webauthn.User interface.
func (u *webauthnUser) WebAuthnDisplayName() string {
	return u.Identity.Name
}

// WebAuthnIcon implements the webauthn.User interface.
func (u *webauthnUser) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials implements the webauthn.User interface.
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	var creds []webauthn.Credential
	for _, c := range u.Credentials {
		creds = append(creds, webauthn.Credential{
			ID:              c.ID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AuthenticatorGUID,
				SignCount: c.AuthenticatorSignCount,
			},
		})
	}
	return creds
}

func (u *webauthnUser) refreshCredentials(ctx context.Context, st store.Store) error {
	credentials, err := st.UserMFACredentials(ctx, string(u.ProviderID))
	if err != nil {
		return errgo.Mask(err)
	}
	u.Credentials = credentials
	return nil
}

// LoginState holds the state of the current multi-factor
// authentication login process.
type LoginState struct {
	// ProviderID holds the provider ID of the user that entered the
	// correct username-password combination.
	ProviderID string
	// RegistrationSessionData holds data associated with the
	// ongoing mfa security device registration process.
	RegistrationSessionData string
	// LoginSessionData holds data associated with the
	// ongoing mfa login process.
	LoginSessionData string
	// ValidCredentialID holds the ID of the presented
	// valid credential.
	ValidCredentialID []byte
}

// formCredentialParams holds the name of the mfa credential along with the url
// where the user may remove the credential.
type formCredentialParams struct {
	Name      string `json:"name"`
	RemoveURL string `json:"removeurl"`
}

// formParams holds parameters for the "mfa" template.
type formParams struct {
	Error            string
	RegistrationURL  string
	LoginURL         string
	MFAState         string
	Note             string
	LoginData        string
	MustRegister     bool
	RegistrationData string
	Credentials      []formCredentialParams
}

// Authenticator implements methods needed for mfa.
type Authenticator struct {
	// Params holds the parameters passed to the identity provider.
	Params idp.InitParams
	// Authenticator holds the webauthn authenticator.
	Authenticator *webauthn.WebAuthn
}

// NewAuthenticator returns a new multi-factor authenticator.
func NewAuthenticator(id, name, origin string) (*Authenticator, error) {
	var err error
	auth, err := webauthn.New(&webauthn.Config{
		RPDisplayName: name,
		RPID:          id,
		RPOrigin:      origin,
	})
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &Authenticator{
		Authenticator: auth,
	}, nil
}

// Init sets the initial paramaters for the authenticator.
func (a *Authenticator) Init(params idp.InitParams) {
	a.Params = params
}

// SetMFAStateProviderID sets the provider id in the mfa login state cookie.
func (a *Authenticator) SetMFAStateProviderID(w http.ResponseWriter, providerID string) (string, error) {
	loginState := LoginState{
		ProviderID: providerID,
	}
	cookiePath := idputil.CookiePathRelativeToLocation(CookiePath, a.Params.Location, a.Params.SkipLocationForCookiePaths)
	mfaState, err := a.Params.Codec.SetCookie(w, CookieName, cookiePath, loginState)
	if err != nil {
		return "", errgo.Mask(err)
	}
	return mfaState, nil
}

func (a *Authenticator) returnError(w http.ResponseWriter, err error) {
	perr, ok := err.(*params.Error)
	if !ok {
		httprequest.WriteJSON(w, http.StatusInternalServerError, err)
	}
	status := http.StatusOK
	switch perr.Code {
	case params.ErrBadRequest:
		status = http.StatusBadRequest
	case params.ErrForbidden:
		status = http.StatusForbidden
	case params.ErrInternalServer:
		status = http.StatusInternalServerError
	}
	httprequest.WriteJSON(
		w,
		status,
		err,
	)
}

// Handle servers incoming http requests.
func (a *Authenticator) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	switch strings.TrimPrefix(req.URL.Path, a.Params.URLPrefix) {
	case "/login":
		switch req.Method {
		case "POST":
			a.login(ctx, w, req)
		case "GET":
			var loginState idputil.LoginState
			if err := a.Params.Codec.Cookie(req, idputil.LoginCookieName, req.Form.Get("state"), &loginState); err != nil {
				idputil.BadRequestf(w, "login failed: invalid login state")
				return
			}

			id, err := a.verifyLogin(ctx, req)
			if err == nil {
				a.Params.VisitCompleter.RedirectSuccess(ctx, w, req, loginState.ReturnTo, loginState.State, id)
			}
			if errgo.Cause(err) == errNoValidCredentials {
				data, err := a.prepareFormData(ctx, w, req)
				if err != nil {
					a.Params.VisitCompleter.RedirectFailure(ctx, w, req, loginState.ReturnTo, loginState.State, errgo.Notef(err, "failed to prepare mfa form"))
				}
				err = a.Params.Template.ExecuteTemplate(w, "mfa", data)
				if err != nil {
					a.Params.VisitCompleter.RedirectFailure(ctx, w, req, loginState.ReturnTo, loginState.State, err)
				}
				return
			}
			a.Params.VisitCompleter.RedirectFailure(ctx, w, req, loginState.ReturnTo, loginState.State, errgo.New("mfa credentials not presented"))
			return
		}
	case "/remove":
		a.removeCredential(ctx, w, req)
	case "/register":
		a.credentialRegistration(ctx, w, req)
	case "/manage":
		a.manage(ctx, w, req)
	}
}

// webAuthnUser fetches the identity with the specified providerID
// and its credentials and returns a type that implements the webauthn.User
// interface.
func (a *Authenticator) webAuthnUser(ctx context.Context, providerID string) (*webauthnUser, error) {
	id := store.Identity{
		ProviderID: store.ProviderIdentity(providerID),
	}
	// we fetch the identity to fill in the username and name
	// fields of the user.
	err := a.Params.Store.Identity(ctx, &id)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	credentials, err := a.Params.Store.UserMFACredentials(ctx, string(id.ProviderID))
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &webauthnUser{
		Identity:    &id,
		Credentials: credentials,
	}, nil
}

func (a *Authenticator) userCredentials(req *http.Request, user *webauthnUser) []formCredentialParams {
	creds := make([]formCredentialParams, len(user.Credentials))
	for i, cred := range user.Credentials {
		v := url.Values{
			"credential-name": {cred.Name},
		}
		creds[i] = formCredentialParams{
			Name:      cred.Name,
			RemoveURL: a.Params.URLPrefix + "/remove?" + v.Encode(),
		}
	}
	return creds
}

// registrationData returns the data needed to register a new
// credential.
func (a *Authenticator) registrationData(ctx context.Context, user webauthn.User) (string, string, error) {
	credentialCreation, registrationSessionData, err := a.Authenticator.BeginRegistration(
		user,
		webauthn.WithAuthenticatorSelection(
			protocol.AuthenticatorSelection{
				RequireResidentKey: protocol.ResidentKeyUnrequired(),
				UserVerification:   protocol.VerificationDiscouraged,
			}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		return "", "", errgo.Mask(err)
	}

	credentialCreationData, err := json.Marshal(credentialCreation)
	if err != nil {
		return "", "", errgo.Mask(err)
	}
	sessionData, err := json.Marshal(registrationSessionData)
	if err != nil {
		return "", "", errgo.Mask(err)
	}
	return string(credentialCreationData), string(sessionData), nil
}

// loginData returns the data needed to verify any existing
// user credential.
func (a *Authenticator) loginData(ctx context.Context, user webauthn.User) (string, string, error) {
	loginOptions, loginSessionData, err := a.Authenticator.BeginLogin(
		user,
		webauthn.WithUserVerification(protocol.VerificationDiscouraged),
	)
	if err != nil {
		return "", "", errgo.Mask(err)
	}
	loginData, err := json.Marshal(loginOptions)
	if err != nil {
		return "", "", errgo.Mask(err)
	}
	sessionData, err := json.Marshal(loginSessionData)
	if err != nil {
		return "", "", errgo.Mask(err)
	}
	return string(loginData), string(sessionData), nil
}

// prepareFormData presents data needed to present a form to the user
// enabling the user to either register a new security device or login using
// an existing device.
func (a *Authenticator) prepareFormData(ctx context.Context, w http.ResponseWriter, req *http.Request) (*formParams, error) {
	var state LoginState
	if err := a.Params.Codec.Cookie(req, CookieName, req.Form.Get(StateName), &state); err != nil {
		return nil, errgo.Mask(err)
	}
	user, err := a.webAuthnUser(ctx, state.ProviderID)
	if err != nil {
		if errgo.Cause(err) == store.ErrNotFound {
			return nil, errgo.WithCausef(nil, params.ErrForbidden, "forbidden")
		}
		return nil, errgo.Mask(err)
	}

	data := formParams{
		RegistrationURL: idputil.RedirectURL(a.Params.URLPrefix, "/register", req.Form.Get("state")),
		LoginURL:        idputil.RedirectURL(a.Params.URLPrefix, "/login", req.Form.Get("state")),
		Credentials:     a.userCredentials(req, user),
	}

	registrationData, registrationSessionData, err := a.registrationData(ctx, user)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	state.RegistrationSessionData = registrationSessionData
	data.RegistrationData = registrationData

	// if the user already has registered security devices, we
	// enable login using any of them
	if len(user.WebAuthnCredentials()) > 0 {
		loginData, sessionData, err := a.loginData(ctx, user)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		state.LoginSessionData = sessionData
		data.LoginData = loginData
	} else {
		data.LoginData = "{}"
		data.MustRegister = true
	}

	cookiePath := idputil.CookiePathRelativeToLocation(CookiePath, a.Params.Location, a.Params.SkipLocationForCookiePaths)
	mfaState, err := a.Params.Codec.SetCookie(w, CookieName, cookiePath, state)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	data.MFAState = mfaState

	if len(user.Credentials) == 0 {
		data.Note = "Identity provider requires MFA. Please register a security key."
	}

	return &data, nil
}

// credentialRegistration method is used to finish the mfa security device registration.
func (a *Authenticator) credentialRegistration(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	// get the credential name from the request
	credentialName := req.Form.Get("credential-name")
	if credentialName == "" {
		a.returnError(w, params.NewError(params.ErrBadRequest, "credential name not specified"))
	}

	// get the login state
	var state LoginState
	if err := a.Params.Codec.Cookie(req, CookieName, req.Form.Get(StateName), &state); err != nil {
		a.returnError(w, params.NewError(params.ErrBadRequest, "invalid mfa login state"))
		return
	}
	// get the user specified in the login state
	user, err := a.webAuthnUser(ctx, state.ProviderID)
	if err != nil {
		if errgo.Cause(err) == store.ErrNotFound {
			a.returnError(w, params.NewError(params.ErrForbidden, "forbidden"))
			return
		}
		a.returnError(w, params.NewError(params.ErrInternalServer, "internal server error"))
		return
	}
	// unmarshal the registration session data
	var sessionData webauthn.SessionData
	err = json.Unmarshal([]byte(state.RegistrationSessionData), &sessionData)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, "invalid session data"))
		return
	}
	// verify the response
	credential, err := a.Authenticator.FinishRegistration(user, sessionData, req)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}
	// add the user's mfa credential to the store
	err = a.Params.Store.AddMFACredential(ctx, store.MFACredential{
		ProviderID:             user.Identity.ProviderID,
		Name:                   credentialName,
		ID:                     credential.ID,
		PublicKey:              credential.PublicKey,
		AttestationType:        credential.AttestationType,
		AuthenticatorGUID:      credential.Authenticator.AAGUID,
		AuthenticatorSignCount: credential.Authenticator.SignCount,
	})
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}

	// refresh user credentials
	err = user.refreshCredentials(ctx, a.Params.Store)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}

	// set the newly registered credentials as the currently valid credential
	// for this user
	state.ValidCredentialID = credential.ID

	registrationData, registrationSessionData, err := a.registrationData(ctx, user)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}
	state.RegistrationSessionData = registrationSessionData

	cookiePath := idputil.CookiePathRelativeToLocation(CookiePath, a.Params.Location, a.Params.SkipLocationForCookiePaths)
	mfaState, err := a.Params.Codec.SetCookie(w, CookieName, cookiePath, state)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}

	// respond with the updated state and user credentials
	creds := a.userCredentials(req, user)
	data := struct {
		State            string                 `json:"state"`
		Credentials      []formCredentialParams `json:"credentials"`
		RegistrationData string                 `json:"registrationdata"`
	}{
		State:            mfaState,
		Credentials:      creds,
		RegistrationData: registrationData,
	}

	httprequest.WriteJSON(w, http.StatusOK, data)
}

// verifyLogin returns an error if the user has not yet presented valid mfa credentials.
func (a *Authenticator) verifyLogin(ctx context.Context, req *http.Request) (*store.Identity, error) {
	// get the login state
	var state LoginState
	if err := a.Params.Codec.Cookie(req, CookieName, req.Form.Get(StateName), &state); err != nil {
		return nil, errgo.New("login state not found")
	}
	// verify that the user has previously presented valid credentials
	if len(state.ValidCredentialID) == 0 {
		return nil, errNoValidCredentials
	}
	// fetch and return the user's identity
	id := store.Identity{
		ProviderID: store.ProviderIdentity(state.ProviderID),
	}
	err := a.Params.Store.Identity(ctx, &id)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &id, nil
}

// login method is used to complete the mfa part of the login process.
func (a *Authenticator) login(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	// get the login state
	var state LoginState
	if err := a.Params.Codec.Cookie(req, CookieName, req.Form.Get(StateName), &state); err != nil {
		a.returnError(w, params.NewError(params.ErrBadRequest, "invalid mfa login state"))
		return
	}
	// get the user specified in the login state
	user, err := a.webAuthnUser(ctx, state.ProviderID)
	if err != nil {
		if errgo.Cause(err) == store.ErrNotFound {
			a.returnError(w, params.NewError(params.ErrForbidden, "forbidden"))
			return
		}
		a.returnError(w, params.NewError(params.ErrInternalServer, "internal server error"))
		return
	}
	// unmarshal the login session data
	var sessionData webauthn.SessionData
	err = json.Unmarshal([]byte(state.LoginSessionData), &sessionData)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}
	// validate presented credentials
	validCredential, err := a.Authenticator.FinishLogin(user, sessionData, req)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrForbidden, err.Error()))
		return
	}
	// update authenticator sig count
	err = a.Params.Store.IncrementMFACredentialSignCount(ctx, validCredential.ID)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}

	// set the presented credenitals as currently valid credentials for the user
	state.ValidCredentialID = validCredential.ID

	registrationData, registrationSessionData, err := a.registrationData(ctx, user)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}
	state.RegistrationSessionData = registrationSessionData

	cookiePath := idputil.CookiePathRelativeToLocation(CookiePath, a.Params.Location, a.Params.SkipLocationForCookiePaths)
	mfaState, err := a.Params.Codec.SetCookie(w, CookieName, cookiePath, state)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}

	// respond with the new state, user credentials, and data
	// that can be used to register new credentials
	creds := a.userCredentials(req, user)
	data := struct {
		State            string                 `json:"state"`
		Credentials      []formCredentialParams `json:"credentials"`
		RegistrationData string                 `json:"registrationdata"`
	}{
		State:            mfaState,
		Credentials:      creds,
		RegistrationData: registrationData,
	}

	httprequest.WriteJSON(w, http.StatusOK, data)
}

// removeCredential removes the user's mfa security device.
func (a *Authenticator) removeCredential(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	// get the login state
	var state LoginState
	if err := a.Params.Codec.Cookie(req, CookieName, req.Form.Get(StateName), &state); err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}

	// get the credential name from the request
	credentialName := req.Form.Get("credential-name")

	// fetch the user specified in the login state
	user, err := a.webAuthnUser(ctx, state.ProviderID)
	if err != nil {
		if errgo.Cause(err) == store.ErrNotFound {
			a.returnError(w, params.NewError(params.ErrForbidden, "forbidden"))
			return
		}
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}

	// remove credentials
	err = a.Params.Store.RemoveMFACredential(ctx, state.ProviderID, credentialName)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}

	err = user.refreshCredentials(ctx, a.Params.Store)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}

	creds := a.userCredentials(req, user)
	data := struct {
		Credentials []formCredentialParams `json:"credentials"`
	}{
		Credentials: creds,
	}

	httprequest.WriteJSON(w, http.StatusOK, data)
}

func (a *Authenticator) manage(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	data, err := a.prepareFormData(ctx, w, req)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}

	err = a.Params.Template.ExecuteTemplate(w, "mfa-manage", data)
	if err != nil {
		a.returnError(w, params.NewError(params.ErrInternalServer, err.Error()))
		return
	}
}
