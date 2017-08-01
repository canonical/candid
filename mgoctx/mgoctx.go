// Copyright 2017 Canonical Ltd.

package mgoctx

import (
	"golang.org/x/net/context"
	mgo "gopkg.in/mgo.v2"
)

type sessionKey struct{}

// ContextWithSession returns the given context with the given session
// attached.
func ContextWithSession(ctx context.Context, s *mgo.Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionFromContext returns the mgo.Session associated with the context
// by ContextWithSession. If there is no session associated with the
// context the returned value will be nil.
func SessionFromContext(ctx context.Context) *mgo.Session {
	s, _ := ctx.Value(sessionKey{}).(*mgo.Session)
	return s
}
