// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"

	"github.com/canonical/candid/candidtest"
	"github.com/canonical/candid/store"
)

type findSuite struct {
	fixture *fixture
}

func TestFind(t *testing.T) {
	qtsuite.Run(qt.New(t), &findSuite{})
}

func (s *findSuite) Init(c *qt.C) {
	s.fixture = newFixture(c)
}

func (s *findSuite) TestFindEmail(c *qt.C) {
	ctx := context.Background()
	candidtest.AddIdentity(ctx, s.fixture.store, &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Email:      "bob@example.com",
	})
	stdout := s.fixture.CheckSuccess(c, "find", "-a", "admin.agent", "-e", "bob@example.com")
	c.Assert(stdout, qt.Equals, "bob\n")
}

func (s *findSuite) TestFindEmailNotFound(c *qt.C) {
	stdout := s.fixture.CheckSuccess(c, "find", "-a", "admin.agent", "-e", "bob@example.com")
	c.Assert(stdout, qt.Equals, "\n")
}

func (s *findSuite) TestFindNoParameters(c *qt.C) {
	ctx := context.Background()
	identites := []store.Identity{{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Email:      "bob@example.com",
	}, {
		ProviderID: store.MakeProviderIdentity("test", "alice"),
		Username:   "alice",
	}, {
		ProviderID: store.MakeProviderIdentity("test", "charlie"),
		Username:   "charlie",
	}}
	for _, id := range identites {
		candidtest.AddIdentity(ctx, s.fixture.store, &id)
	}
	stdout := s.fixture.CheckSuccess(c, "find", "-a", "admin.agent", "--format", "json")
	var usernames []string
	err := json.Unmarshal([]byte(stdout), &usernames)
	c.Assert(err, qt.IsNil)
	c.Assert(usernames, qt.DeepEquals, []string{"admin@candid", "alice", "bob", "charlie"})
}

func (s *findSuite) TestFindLastLoginTime(c *qt.C) {
	ctx := context.Background()
	identities := []store.Identity{{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Email:      "bob@example.com",
		LastLogin:  time.Now().Add(-31 * 24 * time.Hour),
	}, {
		ProviderID: store.MakeProviderIdentity("test", "alice"),
		Username:   "alice",
		LastLogin:  time.Now().Add(-10 * 24 * time.Hour),
	}, {
		ProviderID: store.MakeProviderIdentity("test", "charlie"),
		Username:   "charlie",
		LastLogin:  time.Now().Add(-1 * 24 * time.Hour),
	}}
	for _, id := range identities {
		candidtest.AddIdentity(ctx, s.fixture.store, &id)
	}
	stdout := s.fixture.CheckSuccess(c, "find", "-a", "admin.agent", "--format", "json", "--last-login", "30")
	var usernames []string
	err := json.Unmarshal([]byte(stdout), &usernames)
	c.Assert(err, qt.IsNil)
	c.Assert(usernames, qt.DeepEquals, []string{"alice", "charlie"})
}

func (s *findSuite) TestFindLastDischargeTime(c *qt.C) {
	ctx := context.Background()
	identities := []store.Identity{{
		ProviderID:    store.MakeProviderIdentity("test", "bob"),
		Username:      "bob",
		Email:         "bob@example.com",
		LastDischarge: time.Now().Add(-31 * 24 * time.Hour),
	}, {
		ProviderID:    store.MakeProviderIdentity("test", "alice"),
		Username:      "alice",
		LastDischarge: time.Now().Add(-10 * 24 * time.Hour),
	}, {
		ProviderID:    store.MakeProviderIdentity("test", "charlie"),
		Username:      "charlie",
		LastDischarge: time.Now().Add(-1 * 24 * time.Hour),
	}}
	for _, id := range identities {
		candidtest.AddIdentity(ctx, s.fixture.store, &id)
	}
	stdout := s.fixture.CheckSuccess(c, "find", "-a", "admin.agent", "--format", "json", "--last-discharge", "20")
	var usernames []string
	err := json.Unmarshal([]byte(stdout), &usernames)
	c.Assert(err, qt.IsNil)
	c.Assert(usernames, qt.DeepEquals, []string{"admin@candid", "alice", "charlie"})
}

func (s *findSuite) TestFindWithEmail(c *qt.C) {
	ctx := context.Background()
	identities := []store.Identity{{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Email:      "bob@example.com",
	}, {
		ProviderID: store.MakeProviderIdentity("test", "alice"),
		Username:   "alice",
		Email:      "alice@example.com",
	}, {
		ProviderID: store.MakeProviderIdentity("test", "charlie"),
		Username:   "charlie",
		Email:      "charlie@example.com",
	}}
	for _, id := range identities {
		candidtest.AddIdentity(ctx, s.fixture.store, &id)
	}
	stdout := s.fixture.CheckSuccess(c, "find", "-a", "admin.agent", "-d", "email", "--format", "json")
	var usernames []map[string]string
	err := json.Unmarshal([]byte(stdout), &usernames)
	c.Assert(err, qt.IsNil)
	c.Assert(usernames, qt.DeepEquals, []map[string]string{
		{"username": "admin@candid", "email": ""},
		{"username": "alice", "email": "alice@example.com"},
		{"username": "bob", "email": "bob@example.com"},
		{"username": "charlie", "email": "charlie@example.com"},
	})
}

func (s *findSuite) TestFindWithEmailAndGravatar(c *qt.C) {
	ctx := context.Background()
	identities := []store.Identity{{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
		Email:      "bob@example.com",
	}, {
		ProviderID: store.MakeProviderIdentity("test", "alice"),
		Username:   "alice",
		Email:      "alice@example.com",
	}, {
		ProviderID: store.MakeProviderIdentity("test", "charlie"),
		Username:   "charlie",
		Email:      "charlie@example.com",
	}}
	for _, id := range identities {
		candidtest.AddIdentity(ctx, s.fixture.store, &id)
	}
	stdout := s.fixture.CheckSuccess(c, "find", "-a", "admin.agent", "-d", "email, gravatar_id", "--format", "json")
	var usernames []map[string]string
	err := json.Unmarshal([]byte(stdout), &usernames)
	c.Assert(err, qt.IsNil)
	c.Assert(usernames, qt.DeepEquals, []map[string]string{
		{"username": "admin@candid", "email": "", "gravatar_id": ""},
		{"username": "alice", "email": "alice@example.com", "gravatar_id": "c160f8cc69a4f0bf2b0362752353d060"},
		{"username": "bob", "email": "bob@example.com", "gravatar_id": "4b9bb80620f03eb3719e0a061c14283d"},
		{"username": "charlie", "email": "charlie@example.com", "gravatar_id": "426b189df1e2f359efe6ee90f2d2030f"},
	})
}
