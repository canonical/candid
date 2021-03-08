// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package store_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"gopkg.in/canonical/candid.v2/store"
)

func TestProviderIdentity(t *testing.T) {
	c := qt.New(t)
	pid := store.MakeProviderIdentity("test", "test-id")
	c.Assert(pid, qt.Equals, store.ProviderIdentity("test:test-id"))
	prov, id := pid.Split()
	c.Assert(prov, qt.Equals, "test")
	c.Assert(id, qt.Equals, "test-id")
}
