// Copyright 2017 Canonical Ltd.

package auth

import (
	"golang.org/x/net/context"
)

type contextKey int

const (
	userCredentialsKey contextKey = iota
	requiredDomainKey
	storeKey
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
