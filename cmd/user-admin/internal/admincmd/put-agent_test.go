// Copyright 2017 Canonical Ltd.

package admincmd_test

import (
	"encoding/json"
	"path/filepath"

	"github.com/CanonicalLtd/blues-identity/cmd/user-admin/internal/admincmd"
	"github.com/juju/idmclient"
	"github.com/juju/idmclient/params"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent"
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
	about:       "no username",
	expectError: `missing agent username argument`,
}, {
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
	expectError: `invalid value "xxx" for flag -k: cannot decode base64 key: .*`,
}}

func (s *putAgentSuite) TestUsage(c *gc.C) {
	for i, test := range putAgentUsageTests {
		c.Logf("test %d: %v", i, test.about)
		CheckError(c, 2, test.expectError, s.Run, append([]string{"put-agent"}, test.args...)...)
	}
}

func (s *putAgentSuite) TestPutAgentWithGeneratedKeyAndNoAgentsFile(c *gc.C) {
	var calledReq *params.SetUserRequest
	runf := s.RunServer(c, &handler{
		setUser: func(req *params.SetUserRequest) error {
			calledReq = req
			return nil
		},
	})
	out := CheckSuccess(c, runf, "put-agent", "-a", "admin.agent", "bob@someone")
	c.Assert(calledReq, gc.NotNil)
	// The output should be valid input to an agent.Visitor unmarshal.
	var v agent.Visitor
	err := json.Unmarshal([]byte(out), &v)
	c.Assert(err, gc.Equals, nil)

	// Check that the public key looks right.
	agents := v.Agents()
	c.Assert(agents, gc.HasLen, 1)
	c.Assert(calledReq.PublicKeys, gc.HasLen, 1)
	c.Assert(&agents[0].Key.Public, gc.DeepEquals, calledReq.PublicKeys[0])
	c.Assert(agents[0].URL, gc.Matches, "https://.*")
	c.Assert(agents[0].Username, gc.Equals, "bob@someone")

	calledReq.PublicKeys = nil
	c.Assert(calledReq, jc.DeepEquals, &params.SetUserRequest{
		Username: "bob@someone",
		User: params.User{
			Owner: "someone",
		},
	})
}

func (s *putAgentSuite) TestPutAgentWithNonExistentAgentsFile(c *gc.C) {
	var calledReq *params.SetUserRequest
	runf := s.RunServer(c, &handler{
		setUser: func(req *params.SetUserRequest) error {
			calledReq = req
			return nil
		},
	})
	agentFile := filepath.Join(c.MkDir(), ".agents")
	out := CheckSuccess(c, runf, "put-agent", "-a", "admin.agent", "-f", agentFile, "bob@someone")
	c.Assert(calledReq, gc.NotNil)
	c.Assert(out, gc.Matches, `updated agent bob@someone for https://.* in .+\n`)

	v, err := admincmd.ReadAgentFile(agentFile)
	c.Assert(err, gc.Equals, nil)

	agents := v.Agents()
	c.Assert(agents, gc.HasLen, 1)
	c.Assert(calledReq.PublicKeys, gc.HasLen, 1)
	c.Assert(&agents[0].Key.Public, gc.DeepEquals, calledReq.PublicKeys[0])
	c.Assert(agents[0].URL, gc.Matches, "https://.*")
	c.Assert(agents[0].Username, gc.Equals, "bob@someone")

	calledReq.PublicKeys = nil
	c.Assert(calledReq, jc.DeepEquals, &params.SetUserRequest{
		Username: "bob@someone",
		User: params.User{
			Owner: "someone",
		},
	})
}

func (s *putAgentSuite) TestPutAgentWithNFlag(c *gc.C) {
	// With the -n flag, it doesn't contact the idm server at all.
	out := CheckSuccess(c, s.Run, "put-agent", "-n", "admin@idm")
	var v agent.Visitor
	err := json.Unmarshal([]byte(out), &v)
	c.Assert(err, gc.Equals, nil)
	agents := v.Agents()
	c.Assert(agents, gc.HasLen, 1)
	c.Assert(agents[0].Username, gc.Equals, "admin@idm")
	c.Assert(agents[0].URL, gc.Equals, idmclient.Production)
}

func (s *putAgentSuite) TestInferOwner(c *gc.C) {
	var calledReq *params.SetUserRequest
	runf := s.RunServer(c, &handler{
		setUser: func(req *params.SetUserRequest) error {
			calledReq = req
			return nil
		},
		whoAmI: func(*params.WhoAmIRequest) (*params.WhoAmIResponse, error) {
			return &params.WhoAmIResponse{
				User: "nemo",
			}, nil
		},
	})
	out := CheckSuccess(c, runf, "put-agent", "-a", "admin.agent", "myagent")
	c.Assert(calledReq, gc.NotNil)

	var v agent.Visitor
	err := json.Unmarshal([]byte(out), &v)
	c.Assert(err, gc.Equals, nil)

	// Check that the public key looks right.
	agents := v.Agents()
	c.Assert(agents, gc.HasLen, 1)
	c.Assert(calledReq.PublicKeys, gc.HasLen, 1)
	c.Assert(agents[0].Username, gc.Equals, "myagent@nemo")
}
