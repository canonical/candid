// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd_test

import (
	"bytes"
	"context"
	"io/ioutil"
	"path/filepath"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/cmd"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/canonical/candid/candidtest"
	"github.com/canonical/candid/cmd/candid/internal/admincmd"
	internalcandidtest "github.com/canonical/candid/internal/candidtest"
	"github.com/canonical/candid/store"
)

type fixture struct {
	Dir string

	command cmd.Command
	server  *candidtest.Server
}

func newFixture(c *qt.C) *fixture {
	f := new(fixture)

	srv, err := candidtest.New(nil)
	c.Assert(err, qt.Equals, nil)
	c.Defer(func() {
		srv.Close()
	})
	f.server = srv

	f.Dir = c.Mkdir()
	// If the cookiejar gets saved, it gets saved to $HOME/.go-cookiejar, so make
	// sure that's not in the current directory.
	c.Setenv("HOME", f.Dir)
	c.Setenv("CANDID_URL", f.server.URL)
	err = admincmd.WriteAgentFile(filepath.Join(f.Dir, "admin.agent"), &agent.AuthInfo{
		Key: f.server.AdminAgentKey,
		Agents: []agent.Agent{{
			URL:      f.server.URL,
			Username: "admin@candid",
		}},
	})
	c.Assert(err, qt.Equals, nil)

	f.command = admincmd.New()
	internalcandidtest.LogTo(c)
	return f
}

func (s *fixture) CheckNoOutput(c *qt.C, args ...string) {
	stdout := s.CheckSuccess(c, args...)
	c.Assert(stdout, qt.Equals, "")
}

func (s *fixture) CheckSuccess(c *qt.C, args ...string) string {
	code, stdout, stderr := s.Run(args...)
	c.Assert(code, qt.Equals, 0, qt.Commentf("error code %d: (%s)", code, stderr))
	c.Assert(stderr, qt.Equals, "", qt.Commentf("error code %d: (%s)", code, stderr))
	return stdout
}

func (s *fixture) CheckError(c *qt.C, expectCode int, expectMessage string, args ...string) {
	code, stdout, stderr := s.Run(args...)
	c.Assert(code, qt.Equals, expectCode)
	c.Assert(stderr, qt.Matches, "(ERROR|error:) "+expectMessage+"\n")
	c.Assert(stdout, qt.Equals, "")
}

func (s *fixture) Run(args ...string) (code int, stdout, stderr string) {
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

func (s *fixture) RunContext(ctxt *cmd.Context, args ...string) int {
	return cmd.Main(s.command, ctxt, args)
}

func TestLoadCACerts(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	srv, err := candidtest.NewTLS(nil)
	c.Assert(err, qt.Equals, nil)
	defer srv.Close()

	srv.AddIdentity(context.Background(), &store.Identity{
		ProviderID: store.MakeProviderIdentity("test", "bob"),
		Username:   "bob",
	})

	dir := c.Mkdir()
	c.Setenv("HOME", dir)
	c.Setenv("CANDID_URL", srv.URL)
	c.Setenv("BAKERY_AGENT_FILE", filepath.Join(dir, "admin.agent"))
	err = admincmd.WriteAgentFile(filepath.Join(dir, "admin.agent"), &agent.AuthInfo{
		Key: srv.AdminAgentKey,
		Agents: []agent.Agent{{
			URL:      srv.URL,
			Username: "admin@candid",
		}},
	})
	c.Assert(err, qt.Equals, nil)

	certFile := filepath.Join(dir, "cacerts.pem")
	emptyFile := filepath.Join(dir, "empty.pem")
	unreadableFile := filepath.Join(dir, "unreadable.pem")
	nonExistentFile := filepath.Join(dir, "non-existent.pem")

	err = ioutil.WriteFile(certFile, srv.CACert, 0600)
	c.Assert(err, qt.Equals, nil)
	err = ioutil.WriteFile(emptyFile, nil, 0600)
	c.Assert(err, qt.Equals, nil)
	err = ioutil.WriteFile(unreadableFile, nil, 0)
	c.Assert(err, qt.Equals, nil)

	c.Setenv("CANDID_CA_CERTS", emptyFile+":"+unreadableFile+":"+nonExistentFile+"::"+certFile)

	outbuf := new(bytes.Buffer)
	errbuf := new(bytes.Buffer)
	ctxt := &cmd.Context{
		Dir:    dir,
		Stdin:  bytes.NewReader(nil),
		Stdout: outbuf,
		Stderr: errbuf,
	}

	code := cmd.Main(admincmd.New(), ctxt, []string{"show", "-u", "bob"})
	c.Assert(code, qt.Equals, 0, qt.Commentf("%s", errbuf.String()))

	c.Assert(outbuf.String(), qt.Equals, `
username: bob
external-id: test:bob
name: ""
email: ""
groups: []
ssh-keys: []
last-login: never
last-discharge: never
`[1:])

	c.Assert(errbuf.String(), qt.Equals, "")
}
