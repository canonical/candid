// Copyright 2017 Canonical Ltd.

package auth

var (
	NewChecker         = newChecker
	AuthorizerACLForOp = (*Authorizer).aclForOp
)

const CheckersNamespace = checkersNamespace
