// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"encoding/json"
	"path/filepath"

	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/candid/cmd/candid/internal/admincmd"
	"github.com/CanonicalLtd/candid/store"
)

type createAgentSuite struct {
	commandSuite
}

var _ = gc.Suite(&createAgentSuite{})

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

func (s *createAgentSuite) TestUsage(c *gc.C) {
	for i, test := range createAgentUsageTests {
		c.Logf("test %d: %v", i, test.about)
		s.CheckError(c, 2, test.expectError, append([]string{"create-agent"}, test.args...)...)
	}
}

func (s *createAgentSuite) TestCreateAgentWithGeneratedKeyAndAgentFileNotSpecified(c *gc.C) {
	out := s.CheckSuccess(c, "create-agent", "--name", "agentname", "-a", "admin.agent")
	// The output should be valid input to an agent.AuthInfo unmarshal.
	var v agent.AuthInfo
	err := json.Unmarshal([]byte(out), &v)
	c.Assert(err, gc.Equals, nil)

	// Check that the public key looks right.
	agents := v.Agents
	c.Assert(agents, gc.HasLen, 1)
	c.Assert(agents[0].URL, gc.Equals, s.server.URL)
	identity := store.Identity{
		Username: agents[0].Username,
	}
	c.Assert(s.server.Store.Identity(context.Background(), &identity), gc.Equals, nil)
	c.Assert(identity.PublicKeys, gc.HasLen, 1)
	c.Assert(identity.PublicKeys[0], gc.Equals, v.Key.Public)
}

func (s *createAgentSuite) TestCreateAgentWithNonExistentAgentsFileSpecified(c *gc.C) {
	agentFile := filepath.Join(c.MkDir(), ".agents")
	out := s.CheckSuccess(c, "create-agent", "-a", "admin.agent", "-f", agentFile)
	c.Assert(out, gc.Matches, `added agent a-[0-9a-f]+@candid for http://.* to .+\n`)

	v, err := admincmd.ReadAgentFile(agentFile)
	c.Assert(err, gc.Equals, nil)

	agents := v.Agents
	c.Assert(agents, gc.HasLen, 1)
	c.Assert(agents[0].URL, gc.Equals, s.server.URL)
	identity := store.Identity{
		Username: agents[0].Username,
	}
	c.Assert(s.server.Store.Identity(context.Background(), &identity), gc.Equals, nil)
	c.Assert(identity.PublicKeys, gc.HasLen, 1)
	c.Assert(identity.PublicKeys[0], gc.Equals, v.Key.Public)
	c.Assert(identity.Owner, gc.Equals, store.MakeProviderIdentity("idm", "admin"))
}

func (s *createAgentSuite) TestCreateAgentWithExistingAgentsFile(c *gc.C) {
	out := s.CheckSuccess(c, "create-agent", "-a", "admin.agent", "-f", "admin.agent", "somegroup")
	c.Assert(out, gc.Matches, `added agent a-[0-9a-f]+@candid for http://.* to .+\n`)

	v, err := admincmd.ReadAgentFile(filepath.Join(s.Dir, "admin.agent"))
	c.Assert(err, gc.Equals, nil)

	agents := v.Agents
	c.Assert(agents, gc.HasLen, 2)
	c.Assert(agents[1].URL, gc.Equals, s.server.URL)
	identity := store.Identity{
		Username: agents[1].Username,
	}
	err = s.server.Store.Identity(context.Background(), &identity)
	c.Assert(err, gc.Equals, nil)
	c.Assert(identity.Groups, jc.DeepEquals, []string{"somegroup"})
}

func (s *createAgentSuite) TestCreateAgentWithAdminFlag(c *gc.C) {
	// With the -n flag, it doesn't contact the candid server at all.
	out := s.CheckSuccess(c, "create-agent", "--admin")
	var v agent.AuthInfo
	err := json.Unmarshal([]byte(out), &v)
	c.Assert(err, gc.Equals, nil)
	agents := v.Agents
	c.Assert(agents, gc.HasLen, 1)
	c.Assert(agents[0].Username, gc.Equals, "admin@candid")
	c.Assert(agents[0].URL, gc.Equals, s.server.URL)
}
