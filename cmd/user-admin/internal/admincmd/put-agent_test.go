// Copyright 2017 Canonical Ltd.

package admincmd_test

import (
	"encoding/json"
	"path/filepath"

	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/juju/idmclient.v1"
	"gopkg.in/juju/idmclient.v1/params"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/blues-identity/cmd/user-admin/internal/admincmd"
)

type putAgentSuite struct {
	commandSuite
}

var _ = gc.Suite(&putAgentSuite{})

var putAgentUsageTests = []struct {
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

func (s *putAgentSuite) TestUsage(c *gc.C) {
	for i, test := range putAgentUsageTests {
		c.Logf("test %d: %v", i, test.about)
		CheckError(c, 2, test.expectError, s.Run, append([]string{"put-agent"}, test.args...)...)
	}
}

func (s *putAgentSuite) TestPutAgentWithGeneratedKeyAndAgentFileNotSpecified(c *gc.C) {
	var calledReq *params.CreateAgentRequest
	runf := s.RunServer(c, &handler{
		createAgent: func(req *params.CreateAgentRequest) (*params.CreateAgentResponse, error) {
			calledReq = req
			return &params.CreateAgentResponse{
				Username: "a-foo@idm",
			}, nil
		},
	})
	out := CheckSuccess(c, runf, "put-agent", "--name", "agentname", "-a", "admin.agent")
	c.Assert(calledReq, gc.NotNil)
	// The output should be valid input to an agent.Visitor unmarshal.
	var v agent.AuthInfo
	err := json.Unmarshal([]byte(out), &v)
	c.Assert(err, gc.Equals, nil)

	// Check that the public key looks right.
	agents := v.Agents
	c.Assert(agents, gc.HasLen, 1)
	c.Assert(calledReq.PublicKeys, gc.HasLen, 1)
	c.Assert(&v.Key.Public, gc.DeepEquals, calledReq.PublicKeys[0])
	c.Assert(agents[0].URL, gc.Matches, "https://.*")
	c.Assert(agents[0].Username, gc.Matches, "a-.+@idm")

	calledReq.PublicKeys = nil
	c.Assert(calledReq, jc.DeepEquals, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			FullName: "agentname",
		},
	})
}

func (s *putAgentSuite) TestPutAgentWithNonExistentAgentsFileSpecified(c *gc.C) {
	var calledReq *params.CreateAgentRequest
	runf := s.RunServer(c, &handler{
		createAgent: func(req *params.CreateAgentRequest) (*params.CreateAgentResponse, error) {
			calledReq = req
			return &params.CreateAgentResponse{
				Username: "a-foo@idm",
			}, nil
		},
	})
	agentFile := filepath.Join(c.MkDir(), ".agents")
	out := CheckSuccess(c, runf, "put-agent", "-a", "admin.agent", "-f", agentFile)
	c.Assert(calledReq, gc.NotNil)
	c.Assert(out, gc.Matches, `added agent a-foo@idm for https://.* to .+\n`)

	v, err := admincmd.ReadAgentFile(agentFile)
	c.Assert(err, gc.Equals, nil)

	agents := v.Agents
	c.Assert(agents, gc.HasLen, 1)
	c.Assert(calledReq.PublicKeys, gc.HasLen, 1)
	c.Assert(&v.Key.Public, gc.DeepEquals, calledReq.PublicKeys[0])
	c.Assert(agents[0].URL, gc.Matches, "https://.*")
	c.Assert(agents[0].Username, gc.Equals, "a-foo@idm")

	calledReq.PublicKeys = nil
	c.Assert(calledReq, jc.DeepEquals, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{},
	})
}

func (s *putAgentSuite) TestPutAgentWithExistingAgentsFile(c *gc.C) {
	var calledReq *params.CreateAgentRequest
	runf := s.RunServer(c, &handler{
		createAgent: func(req *params.CreateAgentRequest) (*params.CreateAgentResponse, error) {
			calledReq = req
			return &params.CreateAgentResponse{
				Username: "a-foo@idm",
			}, nil
		},
	})
	out := CheckSuccess(c, runf, "put-agent", "-a", "admin.agent", "-f", "admin.agent", "somegroup")
	c.Assert(calledReq, gc.NotNil)
	c.Assert(out, gc.Matches, `added agent a-foo@idm for https://.* to .+\n`)

	v, err := admincmd.ReadAgentFile(filepath.Join(s.Dir, "admin.agent"))
	c.Assert(err, gc.Equals, nil)

	agents := v.Agents
	c.Assert(agents, gc.HasLen, 2)
	c.Assert(calledReq.PublicKeys, gc.HasLen, 1)
	c.Assert(&v.Key.Public, gc.DeepEquals, calledReq.PublicKeys[0])
	c.Assert(agents[1].URL, gc.Matches, "https://.*")
	c.Assert(agents[1].Username, gc.Equals, "a-foo@idm")

	calledReq.PublicKeys = nil
	c.Assert(calledReq, jc.DeepEquals, &params.CreateAgentRequest{
		CreateAgentBody: params.CreateAgentBody{
			Groups: []string{"somegroup"},
		},
	})
}

func (s *putAgentSuite) TestPutAgentWithAdminFlag(c *gc.C) {
	// With the -n flag, it doesn't contact the idm server at all.
	out := CheckSuccess(c, s.Run, "put-agent", "--admin")
	var v agent.AuthInfo
	err := json.Unmarshal([]byte(out), &v)
	c.Assert(err, gc.Equals, nil)
	agents := v.Agents
	c.Assert(agents, gc.HasLen, 1)
	c.Assert(agents[0].Username, gc.Equals, "admin@idm")
	c.Assert(agents[0].URL, gc.Equals, idmclient.Production)
}
