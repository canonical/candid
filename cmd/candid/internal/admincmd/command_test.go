// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"bytes"
	"path/filepath"

	"github.com/juju/cmd"
	"github.com/juju/testing"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/candid/candidtest"
	"github.com/CanonicalLtd/candid/cmd/candid/internal/admincmd"
)

type commandSuite struct {
	testing.IsolationSuite

	Dir string

	command cmd.Command
	server  *candidtest.Server
}

func (s *commandSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	var err error
	s.server, err = candidtest.New(nil)
	c.Assert(err, gc.Equals, nil)
	s.Dir = c.MkDir()
	// If the cookiejar gets saved, it gets saved to $HOME/.go-cookiejar, so make
	// sure that's not in the current directory.
	s.PatchEnvironment("HOME", s.Dir)
	s.PatchEnvironment("CANDID_URL", s.server.URL)
	err = admincmd.WriteAgentFile(filepath.Join(s.Dir, "admin.agent"), &agent.AuthInfo{
		Key: s.server.AdminAgentKey,
		Agents: []agent.Agent{{
			URL:      s.server.URL,
			Username: "admin@candid",
		}},
	})
	c.Assert(err, gc.Equals, nil)

	s.command = admincmd.New()
}

func (s *commandSuite) TearDownTest(c *gc.C) {
	if s.server != nil {
		s.server.Close()
	}
}

func (s *commandSuite) CheckNoOutput(c *gc.C, args ...string) {
	stdout := s.CheckSuccess(c, args...)
	c.Assert(stdout, gc.Equals, "")
}

func (s *commandSuite) CheckSuccess(c *gc.C, args ...string) string {
	code, stdout, stderr := s.Run(args...)
	c.Assert(code, gc.Equals, 0, gc.Commentf("error code %d: (%s)", code, stderr))
	c.Assert(stderr, gc.Equals, "", gc.Commentf("error code %d: (%s)", code, stderr))
	return stdout
}

func (s *commandSuite) CheckError(c *gc.C, expectCode int, expectMessage string, args ...string) {
	code, stdout, stderr := s.Run(args...)
	c.Assert(code, gc.Equals, expectCode)
	c.Assert(stderr, gc.Matches, "(ERROR|error:) "+expectMessage+"\n")
	c.Assert(stdout, gc.Equals, "")
}

func (s *commandSuite) Run(args ...string) (code int, stdout, stderr string) {
	outbuf := new(bytes.Buffer)
	errbuf := new(bytes.Buffer)
	ctxt := &cmd.Context{
		Dir:    s.Dir,
		Stdin:  bytes.NewReader(nil),
		Stdout: outbuf,
		Stderr: errbuf,
	}
	code = s.RunContext(ctxt, args...)
	return code, outbuf.String(), errbuf.String()
}

func (s *commandSuite) RunContext(ctxt *cmd.Context, args ...string) int {
	return cmd.Main(s.command, ctxt, args)
}
