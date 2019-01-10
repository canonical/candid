// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/frankban/quicktest/qtsuite"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/candid/cmd/candid/internal/admincmd"
	"github.com/CanonicalLtd/candid/store"
)

type createAgentSuite struct {
	fixture *fixture
}

func TestCreateAgent(t *testing.T) {
	qtsuite.Run(qt.New(t), &createAgentSuite{})
}

func (s *createAgentSuite) Init(c *qt.C) {
	s.fixture = newFixture(c)
}

var createAgentUsageTests = []struct {
	about       string
	args        []string
	expectError string
}{{
	about:       "agent file and agent key specified together",
	args:        []string{"-k", "S2oglf2m3F7oN6o4d517Y/aRjObgw/S7ZNevIIp+NnQ=", "-f", "foo", "bob"},
	expectError: `cannot specify public key and an agent file`,
}, {
	about:       "empty public key",
	args:        []string{"-k", "", "bob"},
	expectError: `invalid value "" for flag -k: wrong length for key, got 0 want 32`,
}, {
	about:       "invalid public key",
	args:        []string{"-k", "xxx", "bob"},
	expectError: `invalid value "xxx" for flag -k: wrong length for key, got 2 want 32`,
}}

func (s *createAgentSuite) TestUsage(c *qt.C) {
	for i, test := range createAgentUsageTests {
		c.Logf("test %d: %v", i, test.about)
		s.fixture.CheckError(c, 2, test.expectError, append([]string{"create-agent"}, test.args...)...)
	}
}

func (s *createAgentSuite) TestCreateAgentWithGeneratedKeyAndAgentFileNotSpecified(c *qt.C) {
	out := s.fixture.CheckSuccess(c, "create-agent", "--name", "agentname", "-a", "admin.agent")
	// The output should be valid input to an agent.AuthInfo unmarshal.
	var v agent.AuthInfo
	err := json.Unmarshal([]byte(out), &v)
	c.Assert(err, qt.Equals, nil)

	// Check that the public key looks right.
	agents := v.Agents
	c.Assert(agents, qt.HasLen, 1)
	c.Assert(agents[0].URL, qt.Equals, s.fixture.server.URL)
	identity := store.Identity{
		Username: agents[0].Username,
	}
	c.Assert(s.fixture.server.Store.Identity(context.Background(), &identity), qt.Equals, nil)
	c.Assert(identity.PublicKeys, qt.HasLen, 1)
	c.Assert(identity.PublicKeys[0], qt.Equals, v.Key.Public)
}

func (s *createAgentSuite) TestCreateAgentWithNonExistentAgentsFileSpecified(c *qt.C) {
	agentFile := filepath.Join(c.Mkdir(), ".agents")
	out := s.fixture.CheckSuccess(c, "create-agent", "-a", "admin.agent", "-f", agentFile)
	c.Assert(out, qt.Matches, `added agent a-[0-9a-f]+@candid for http://.* to .+\n`)

	v, err := admincmd.ReadAgentFile(agentFile)
	c.Assert(err, qt.Equals, nil)

	agents := v.Agents
	c.Assert(agents, qt.HasLen, 1)
	c.Assert(agents[0].URL, qt.Equals, s.fixture.server.URL)
	identity := store.Identity{
		Username: agents[0].Username,
	}
	c.Assert(s.fixture.server.Store.Identity(context.Background(), &identity), qt.Equals, nil)
	c.Assert(identity.PublicKeys, qt.HasLen, 1)
	c.Assert(identity.PublicKeys[0], qt.Equals, v.Key.Public)
	c.Assert(identity.Owner, qt.Equals, store.MakeProviderIdentity("idm", "admin"))
}

func (s *createAgentSuite) TestCreateAgentWithExistingAgentsFile(c *qt.C) {
	out := s.fixture.CheckSuccess(c, "create-agent", "-a", "admin.agent", "-f", "admin.agent", "somegroup")
	c.Assert(out, qt.Matches, `added agent a-[0-9a-f]+@candid for http://.* to .+\n`)

	v, err := admincmd.ReadAgentFile(filepath.Join(s.fixture.Dir, "admin.agent"))
	c.Assert(err, qt.Equals, nil)

	agents := v.Agents
	c.Assert(agents, qt.HasLen, 2)
	c.Assert(agents[1].URL, qt.Equals, s.fixture.server.URL)
	identity := store.Identity{
		Username: agents[1].Username,
	}
	err = s.fixture.server.Store.Identity(context.Background(), &identity)
	c.Assert(err, qt.Equals, nil)
	c.Assert(identity.Groups, qt.DeepEquals, []string{"somegroup"})
}

func (s *createAgentSuite) TestCreateAgentWithAdminFlag(c *qt.C) {
	// With the -n flag, it doesn't contact the candid server at all.
	out := s.fixture.CheckSuccess(c, "create-agent", "--admin")
	var v agent.AuthInfo
	err := json.Unmarshal([]byte(out), &v)
	c.Assert(err, qt.Equals, nil)
	agents := v.Agents
	c.Assert(agents, qt.HasLen, 1)
	c.Assert(agents[0].Username, qt.Equals, "admin@candid")
	c.Assert(agents[0].URL, qt.Equals, s.fixture.server.URL)
}
func (s *createAgentSuite) TestCreateAgentWithParentFlag(c *qt.C) {
	// With the -n flag, it doesn't contact the candid server at all.
	out := s.fixture.CheckSuccess(c, "create-agent", "-a", "admin.agent", "--parent")
	var v agent.AuthInfo
	err := json.Unmarshal([]byte(out), &v)
	c.Assert(err, qt.Equals, nil)
	agents := v.Agents
	c.Assert(agents, qt.HasLen, 1)
	if !strings.HasPrefix(string(agents[0].Username), "a-") {
		c.Errorf("unexpected agent username %q", agents[0].Username)
	}
	c.Assert(agents[0].URL, qt.Equals, s.fixture.server.URL)
}
