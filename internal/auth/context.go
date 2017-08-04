// Copyright 2017 Canonical Ltd.

package auth

import (
	"golang.org/x/net/context"

	"github.com/CanonicalLtd/blues-identity/internal/store"
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

// ContextWithStore returns a context with the given store attached.
func ContextWithStore(ctx context.Context, store *store.Store) context.Context {
	return context.WithValue(ctx, storeKey, store)
}

func storeFromContext(ctx context.Context) *store.Store {
	st, _ := ctx.Value(storeKey).(*store.Store)
	return st
}
