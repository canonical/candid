# Multi-Factor Authentication

Candid supports WebAuthn multi-factor authentication that can be configured for the
static and LDAP identity providers.

## Supported browsers

WebAuthn is currently supported in Google Chrome, Mozilla Firefox, Microsoft Edge and Apple Safari (preview) web browsers, as well as Windows 10 and Android platforms.

For more info see [link](https://caniuse.com/?search=webauthn).

## Supported authenticators

Candid supports WebAuthn multi-factor authentications, which requires uses to register an external authenticator that supports [FIDO2](https://fidoalliance.org/fido2/fido2-web-authentication-webauthn/) such as Yubikey 5.

The first time a user logs in using an identity provider that is configured to require MFA, the user will be required to register an external authenticator. Following successful registration the user will be able to register multiple other authenticators.

On subsequent logins user will be required to present one of the registered authenticators before completing the login process.

### Lost authenticators

Should the user lose all registered authenticators, the Candid admin can user the **clear-mfa-credentials** command which will de-register all user's authenticators. Next time the user will be required to register a new authenticator.

Example:

> candid clear-mfa-credentials \<username\>
