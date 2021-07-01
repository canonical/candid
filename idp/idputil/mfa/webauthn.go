// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package mfa contains utility routines for multi-factor
// authentication with WebAuthn.
package mfa

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

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

var logger = loggo.GetLogger("candid.idp.idputil.mfa")

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

// MFACookieName holds the name of the multi-factor authentication
// cookie.
const MFACookieName = "candid-login-mfa"

// MFACookiePath is the path to associate with the cookie storing the
// current multi-factor authentication state.
const MFACookiePath = "/login"

// MFALoginState holds the state of the current multi-factor
// authentication login process.
type MFALoginState struct {
	// ProviderID holds the provider ID of the user that entered the
	// correct username-password combination.
	ProviderID string
	// RegistrationSessionData holds data associated with the
	// ongoing 2FA security device registration process.
	RegistrationSessionData string
	// LoginSessionData holds data associated with the
	// ongoing 2FA login process.
	LoginSessionData string
	// ValidCredentialID holds the ID of the presented
	// valid credential.
	ValidCredentialID []byte
}

// MFAFormCredentialParams holds the name of the 2fa credential along with the url
// where the user may remove the credential.
type MFAFormCredentialParams struct {
	Name      string `json:"name"`
	RemoveURL string `json:"removeurl"`
}

// MFAFormParams holds parameters for the "mfa" template.
type MFAFormParams struct {
	Error            string
	RegistrationURL  string
	LoginURL         string
	MFAState         string
	Note             string
	LoginData        string
	RegistrationData string
}

// MultiFactorAuthenticator implements methods needed for 2FA.
type MultiFactorAuthenticator struct {
	// Params holds the parameters passed to the identity provider.
	Params idp.InitParams
	// Authenticator holds the webauthn authenticator.
	Authenticator *webauthn.WebAuthn
}

// webAuthnUserFromIdentity converts the provided store Identity to
// a type that implements the webauthn.User interface.
func (a *MultiFactorAuthenticator) webAuthnUser(ctx context.Context, providerID string) (*webauthnUser, error) {
	id := store.Identity{
		ProviderID: store.ProviderIdentity(providerID),
	}
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

type authError struct {
	Message string `json:"message"`
}

func (a *MultiFactorAuthenticator) registrationData(ctx context.Context, user webauthn.User) (string, string, error) {
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

func (a *MultiFactorAuthenticator) loginData(ctx context.Context, user webauthn.User) (string, string, error) {
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

// FormData fills in the data used to present a form to the user
// enabling the user to either register a new security device or login using
// an existing device.
func (a *MultiFactorAuthenticator) FormData(ctx context.Context, w http.ResponseWriter, req *http.Request, providerID string, data *MFAFormParams) error {
	var state MFALoginState
	validLoginState := true
	if err := a.Params.Codec.Cookie(req, MFACookieName, req.Form.Get("mfa-state"), &state); err != nil {
		validLoginState = false
	}
	state.ProviderID = providerID
	user, err := a.webAuthnUser(ctx, providerID)
	if err != nil {
		if errgo.Cause(err) == store.ErrNotFound {
			return errgo.WithCausef(nil, params.ErrForbidden, "forbidden")
		}
		return errgo.Mask(err)
	}

	// if user has no previously registered credentials or the user
	// has already presented a valid 2fa credential, we allow additional
	// device registration
	if len(user.WebAuthnCredentials()) == 0 || (validLoginState && len(state.ValidCredentialID) != 0) {
		registrationData, registrationSessionData, err := a.registrationData(ctx, user)
		if err != nil {
			return errgo.Mask(err)
		}

		state.RegistrationSessionData = registrationSessionData
		data.RegistrationData = registrationData
	} else {
		data.RegistrationData = "{}"
	}

	// if the user already has registered security devices, we
	// enable login using any of them
	if len(user.WebAuthnCredentials()) > 0 {
		loginData, sessionData, err := a.loginData(ctx, user)
		if err != nil {
			return errgo.Mask(err)
		}
		state.LoginSessionData = sessionData
		data.LoginData = loginData
	} else {
		data.LoginData = "{}"
	}

	cookiePath := idputil.CookiePathRelativeToLocation(MFACookiePath, a.Params.Location, a.Params.SkipLocationForCookiePaths)
	mfaState, err := a.Params.Codec.SetCookie(w, MFACookieName, cookiePath, state)
	if err != nil {
		return errgo.Mask(err)
	}
	data.MFAState = mfaState

	if len(user.Credentials) == 0 {
		data.Note = "Identity provider requires MFA. Please register a security key."
	}

	return nil
}

// FinishSecurityDeviceRegistration method is used to finish the 2FA security device registration.
func (a *MultiFactorAuthenticator) FinishSecurityDeviceRegistration(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	returnError := func(status int, message string) {
		httprequest.WriteJSON(
			w,
			status,
			authError{
				Message: message,
			},
		)
	}
	deviceName := req.Form.Get("name")
	var mfa MFALoginState
	if err := a.Params.Codec.Cookie(req, MFACookieName, req.Form.Get("mfa-state"), &mfa); err != nil {
		logger.Infof("invalid 2fa login state: %s", err)
		returnError(http.StatusBadRequest, "invalid 2fa login state")
		return
	}
	user, err := a.webAuthnUser(ctx, mfa.ProviderID)
	if err != nil {
		if errgo.Cause(err) == store.ErrNotFound {
			returnError(http.StatusForbidden, "forbidden")
			return
		}
		returnError(http.StatusInternalServerError, "internal server error")
		return
	}
	var sessionData webauthn.SessionData
	err = json.Unmarshal([]byte(mfa.RegistrationSessionData), &sessionData)
	if err != nil {
		returnError(http.StatusInternalServerError, "failed to unmarshal session data")
		return
	}
	credential, err := a.Authenticator.FinishRegistration(user, sessionData, req)
	if err != nil {
		returnError(http.StatusInternalServerError, err.Error())
		return
	}
	err = a.Params.Store.AddMFACredential(ctx, store.MFACredential{
		ProviderID:             user.Identity.ProviderID,
		Name:                   deviceName,
		ID:                     credential.ID,
		PublicKey:              credential.PublicKey,
		AttestationType:        credential.AttestationType,
		AuthenticatorGUID:      credential.Authenticator.AAGUID,
		AuthenticatorSignCount: credential.Authenticator.SignCount,
	})
	if err != nil {
		returnError(http.StatusInternalServerError, err.Error())
		return
	}

	user, err = a.webAuthnUser(ctx, mfa.ProviderID)
	if err != nil {
		returnError(http.StatusInternalServerError, "internal server error")
		return
	}

	mfa.ValidCredentialID = credential.ID
	cookiePath := idputil.CookiePathRelativeToLocation(MFACookiePath, a.Params.Location, a.Params.SkipLocationForCookiePaths)
	mfaState, err := a.Params.Codec.SetCookie(w, MFACookieName, cookiePath, mfa)
	if err != nil {
		returnError(http.StatusInternalServerError, "failed to set a cookie")
		return
	}

	creds := a.userCredentials(req, user)
	data := struct {
		State       string                    `json:"state"`
		Credentials []MFAFormCredentialParams `json:"credentials"`
	}{
		State:       mfaState,
		Credentials: creds,
	}

	httprequest.WriteJSON(w, http.StatusOK, data)
}

func (a *MultiFactorAuthenticator) userCredentials(req *http.Request, user *webauthnUser) []MFAFormCredentialParams {
	creds := make([]MFAFormCredentialParams, len(user.Credentials))
	for i, c := range user.Credentials {
		v := url.Values{
			"state":           {req.Form.Get("state")},
			"credential-name": {c.Name},
		}
		creds[i] = MFAFormCredentialParams{
			Name:      c.Name,
			RemoveURL: a.Params.URLPrefix + "/mfa/remove?" + v.Encode(),
		}
	}
	return creds
}

// VerifyLogin returns an error if the user has not yet presented valid 2fa credentials.
func (a *MultiFactorAuthenticator) VerifyLogin(ctx context.Context, req *http.Request) (*store.Identity, error) {
	var state MFALoginState
	if err := a.Params.Codec.Cookie(req, MFACookieName, req.Form.Get("mfa-state"), &state); err != nil {
		return nil, errgo.New("login state not found")
	}
	if len(state.ValidCredentialID) == 0 {
		return nil, errgo.New("no valid credentials presented")
	}
	id := store.Identity{
		ProviderID: store.ProviderIdentity(state.ProviderID),
	}
	err := a.Params.Store.Identity(ctx, &id)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &id, nil
}

// Login method is used to complete the 2FA part of the login process.
func (a *MultiFactorAuthenticator) Login(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	returnError := func(status int, message string) {
		httprequest.WriteJSON(
			w,
			status,
			authError{
				Message: message,
			},
		)
	}
	var mfa MFALoginState
	if err := a.Params.Codec.Cookie(req, MFACookieName, req.Form.Get("mfa-state"), &mfa); err != nil {
		logger.Infof("invalid 2fa login state: %s", err)
		returnError(http.StatusBadRequest, "invalid 2fa login state")
		return
	}
	user, err := a.webAuthnUser(ctx, mfa.ProviderID)
	if err != nil {
		if errgo.Cause(err) == store.ErrNotFound {
			returnError(http.StatusForbidden, "forbidden")
			return
		}
		returnError(http.StatusInternalServerError, "internal server error")
		return
	}
	var sessionData webauthn.SessionData
	err = json.Unmarshal([]byte(mfa.LoginSessionData), &sessionData)
	if err != nil {
		returnError(http.StatusInternalServerError, "could not unmarshal session data")
		return
	}
	validCredential, err := a.Authenticator.FinishLogin(user, sessionData, req)
	if err != nil {
		returnError(http.StatusInternalServerError, err.Error())
		return
	}
	// update authenticator sig count
	err = a.Params.Store.IncrementMFACredentialSignCount(ctx, validCredential.ID)
	if err != nil {
		returnError(http.StatusInternalServerError, "failed to increment authenticator sig count")
		return
	}
	mfa.ValidCredentialID = validCredential.ID
	cookiePath := idputil.CookiePathRelativeToLocation(MFACookiePath, a.Params.Location, a.Params.SkipLocationForCookiePaths)
	mfaState, err := a.Params.Codec.SetCookie(w, MFACookieName, cookiePath, mfa)
	if err != nil {
		returnError(http.StatusInternalServerError, "failed to set a cookie")
		return
	}

	creds := a.userCredentials(req, user)
	data := struct {
		State       string                    `json:"state"`
		Credentials []MFAFormCredentialParams `json:"credentials"`
	}{
		State:       mfaState,
		Credentials: creds,
	}

	httprequest.WriteJSON(w, http.StatusOK, data)
}

// RemoveCredential removes the user's 2FA security device.
func (a *MultiFactorAuthenticator) RemoveCredential(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	returnError := func(status int, message string) {
		httprequest.WriteJSON(
			w,
			status,
			authError{
				Message: message,
			},
		)
	}
	credentialName := req.Form.Get("credential-name")
	var state MFALoginState
	if err := a.Params.Codec.Cookie(req, MFACookieName, req.Form.Get("mfa-state"), &state); err != nil {
		logger.Infof("invalid mfa login state: %s", err)
		returnError(http.StatusBadRequest, "invalid 2fa login state")
		return
	}
	// if no valid credentials were presented, we return
	// an error
	if len(state.ValidCredentialID) == 0 {
		returnError(http.StatusForbidden, "forbidden")
		return
	}

	err := a.Params.Store.RemoveMFACredential(ctx,
		state.ProviderID,
		credentialName,
	)
	if err != nil {
		returnError(http.StatusInternalServerError, "failed to remove user credential")
		return
	}

	user, err := a.webAuthnUser(ctx, state.ProviderID)
	if err != nil {
		if errgo.Cause(err) == store.ErrNotFound {
			returnError(http.StatusForbidden, "forbidden")
			return
		}
		returnError(http.StatusInternalServerError, "internal server error")
		return
	}

	for _, cred := range user.Credentials {
		if bytes.Compare(cred.ID, state.ValidCredentialID) == 0 {
			state.ValidCredentialID = nil
			break
		}
	}

	cookiePath := idputil.CookiePathRelativeToLocation(MFACookiePath, a.Params.Location, a.Params.SkipLocationForCookiePaths)
	mfaState, err := a.Params.Codec.SetCookie(w, MFACookieName, cookiePath, state)
	if err != nil {
		returnError(http.StatusInternalServerError, "failed to set a cookie")
		return
	}

	creds := a.userCredentials(req, user)
	data := struct {
		State       string                    `json:"state"`
		Credentials []MFAFormCredentialParams `json:"credentials"`
	}{
		State:       mfaState,
		Credentials: creds,
	}

	httprequest.WriteJSON(w, http.StatusOK, data)
}
