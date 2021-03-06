// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package store_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	errgo "gopkg.in/errgo.v1"

	"github.com/canonical/candid/v2/store"
)

func TestNotFoundError(t *testing.T) {
	c := qt.New(t)
	err := store.NotFoundError("1234", "", "")
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
	c.Assert(err, qt.ErrorMatches, `identity "1234" not found`)
	err = store.NotFoundError("", store.MakeProviderIdentity("test", "test-user"), "")
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
	c.Assert(err, qt.ErrorMatches, `identity "test:test-user" not found`)
	err = store.NotFoundError("", "", "test-user")
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
	c.Assert(err, qt.ErrorMatches, `user test-user not found`)
	err = store.NotFoundError("", "", "")
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrNotFound)
	c.Assert(err, qt.ErrorMatches, `identity not specified`)
}

func TestDuplicateUsernameError(t *testing.T) {
	c := qt.New(t)
	err := store.DuplicateUsernameError("test-user")
	c.Assert(errgo.Cause(err), qt.Equals, store.ErrDuplicateUsername)
	c.Assert(err, qt.ErrorMatches, `username test-user already in use`)
}
