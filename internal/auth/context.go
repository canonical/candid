// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package auth

import (
	"context"
)

type contextKey int

const (
	userCredentialsKey contextKey = iota
	requiredDomainKey
	dischargeIDKey
	usernameKey
)

type userCredentials struct {
	username, password string
}

// ContextWithUserCredentials returns a context with the given user
// credentials attached. These will then be checked when performing
// authorizations.
func ContextWithUserCredentials(ctx context.Context, username, password string) context.Context {
	return context.WithValue(ctx, userCredentialsKey, userCredentials{username, password})
}

func userCredentialsFromContext(ctx context.Context) (username, password string, ok bool) {
	uc, ok := ctx.Value(userCredentialsKey).(userCredentials)
	return uc.username, uc.password, ok
}

// ContextWithRequiredDomain returns a context associated
// with the given domain, such that declared identities
// will only be allowed if they have that domain.
func ContextWithRequiredDomain(ctx context.Context, domain string) context.Context {
	return context.WithValue(ctx, requiredDomainKey, domain)
}

func requiredDomainFromContext(ctx context.Context) string {
	requiredDomain, _ := ctx.Value(usernameKey).(string)
	return requiredDomain
}

// ContextWithDischargeID returns a context with the given discharge ID
// stored.
func ContextWithDischargeID(ctx context.Context, dischargeID string) context.Context {
	return context.WithValue(ctx, dischargeIDKey, dischargeID)
}

func dischargeIDFromContext(ctx context.Context) string {
	dischargeID, _ := ctx.Value(dischargeIDKey).(string)
	return dischargeID
}

// ContextWithUsername returns a context with the given username stored.
// Any user attached to the context will be considered authenticated by
// IdentityFromContext.
func ContextWithUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, usernameKey, username)
}

func usernameFromContext(ctx context.Context) string {
	username, _ := ctx.Value(usernameKey).(string)
	return username
}
