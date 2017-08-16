// Copyright 2017 Canonical Ltd.

package store_test

import (
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/store"
)

type errorSuite struct{}

var _ = gc.Suite(&errorSuite{})

func (*errorSuite) TestNotFoundError(c *gc.C) {
	err := store.NotFoundError("1234", "", "")
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, `identity "1234" not found`)
	err = store.NotFoundError("", store.MakeProviderIdentity("test", "test-user"), "")
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, `identity "test:test-user" not found`)
	err = store.NotFoundError("", "", "test-user")
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, `user test-user not found`)
	err = store.NotFoundError("", "", "")
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
	c.Assert(err, gc.ErrorMatches, `identity not specified`)
}

func (*errorSuite) TestDuplicateUsernameError(c *gc.C) {
	err := store.DuplicateUsernameError("test-user")
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrDuplicateUsername)
	c.Assert(err, gc.ErrorMatches, `username test-user already in use`)
}

func (*errorSuite) TestDuplicateKeyError(c *gc.C) {
	err := store.DuplicateKeyError("test-key")
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrDuplicateKey)
	c.Assert(err, gc.ErrorMatches, `key test-key already exists`)
}
