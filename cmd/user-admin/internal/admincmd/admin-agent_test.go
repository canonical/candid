// Copyright 2016 Canonical Ltd.

package admincmd_test

import (
	"bytes"
	"strings"

	"github.com/juju/cmd"
	"github.com/juju/testing"
	"github.com/juju/testing/filetesting"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/cmd/user-admin/internal/admincmd"
)

type adminAgentSuite struct {
	commandSuite
}

var _ = gc.Suite(&adminAgentSuite{})

func (s *adminAgentSuite) TestCreateAdminAgent(c *gc.C) {
	stdout := CheckSuccess(c, s.Run, "create-admin-agent")
	a, err := admincmd.Read(strings.NewReader(stdout))
	c.Assert(err, gc.Equals, nil)
	c.Assert(a.Username, gc.Equals, "admin@idm")
	c.Assert(a.PublicKey, gc.Not(gc.IsNil))
	c.Assert(a.PrivateKey, gc.Not(gc.IsNil))
}

func (s *adminAgentSuite) TestCreateAdminAgentWriteError(c *gc.C) {
	stub := new(testing.Stub)
	stub.SetErrors(errgo.New("test error"))
	stdout, _ := filetesting.NewStubWriter(stub)
	stderr := new(bytes.Buffer)
	ctxt := &cmd.Context{
		Dir:    c.MkDir(),
		Stdin:  bytes.NewReader(nil),
		Stdout: stdout,
		Stderr: stderr,
	}
	code := s.RunContext(ctxt, "create-admin-agent")
	c.Assert(code, gc.Not(gc.Equals), 0)
	c.Assert(stderr.String(), gc.Matches, "(ERROR|error) test error\n")
}
