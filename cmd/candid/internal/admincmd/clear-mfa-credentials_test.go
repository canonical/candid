// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"

	"github.com/canonical/candid/candidtest"
	"github.com/canonical/candid/store"
)

type clearMFACredentialsSuite struct {
	fixture *fixture
}

func TestClearMFACredentials(t *testing.T) {
	qtsuite.Run(qt.New(t), &clearMFACredentialsSuite{})
}

func (s *clearMFACredentialsSuite) Init(c *qt.C) {
	s.fixture = newFixture(c)
}

func (s *clearMFACredentialsSuite) TestClearMFACredentials(c *qt.C) {
	ctx := context.Background()
	candidtest.AddIdentity(ctx, s.fixture.store, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
	})
	err := s.fixture.store.AddMFACredential(context.Background(), store.MFACredential{
		ID:         []byte("test-id-1"),
		Name:       "test name",
		ProviderID: store.MakeProviderIdentity("test", "bob"),
	})
	c.Assert(err, qt.Equals, nil)

	s.fixture.CheckNoOutput(c, "clear-mfa-credentials", "-a", "admin.agent", "bob")

	creds, err := s.fixture.store.UserMFACredentials(context.Background(), string(store.MakeProviderIdentity("test", "bob")))
	c.Assert(err, qt.Equals, nil)
	c.Assert(creds, qt.HasLen, 0)
}
