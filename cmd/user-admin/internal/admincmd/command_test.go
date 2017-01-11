// Copyright 2016 Canonical Ltd.

package admincmd_test

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/juju/cmd"
	"github.com/juju/httprequest"
	"github.com/juju/idmclient/idmtest"
	"github.com/juju/idmclient/params"
	"github.com/juju/testing"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/CanonicalLtd/blues-identity/cmd/user-admin/internal/admincmd"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
)

type commandSuite struct {
	testing.IsolationSuite

	Dir string

	command cmd.Command
}

func (s *commandSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	s.Dir = c.MkDir()
	s.command = admincmd.New()
}

func CheckNoOutput(c *gc.C, f func(args ...string) (code int, stdout, stderr string), args ...string) {
	stdout := CheckSuccess(c, f, args...)
	c.Assert(stdout, gc.Equals, "")
}

func CheckSuccess(c *gc.C, f func(args ...string) (code int, stdout, stderr string), args ...string) string {
	code, stdout, stderr := f(args...)
	c.Assert(code, gc.Equals, 0, gc.Commentf("error code %d: (%s)", code, stderr))
	c.Assert(stderr, gc.Equals, "", gc.Commentf("error code %d: (%s)", code, stderr))
	return stdout
}

func CheckError(c *gc.C, expectCode int, expectMessage string, f func(args ...string) (code int, stdout, stderr string), args ...string) {
	code, stdout, stderr := f(args...)
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

// RunServer returns a RunFunc that starts a new server with the
// given handlers, creates a new 'admin.agent' file in s.Dir, sets the
// IDM_URL environment variable to point to the newly created server and
// then runs the given ocmmand line. The command line is expected to
// contain the required flags to use the admin.agent file for login.
func (s *commandSuite) RunServer(c *gc.C, handler *handler) func(args ...string) (code int, stdout, stderr string) {
	return func(args ...string) (code int, stdout, stderr string) {
		server := newServer(handler)
		defer server.Close()
		f, err := os.Create(filepath.Join(s.Dir, "admin.agent"))
		c.Assert(err, gc.Equals, nil)
		defer f.Close()
		ag := server.adminAgent()
		err = admincmd.Write(f, ag)
		c.Assert(err, gc.Equals, nil)
		s.PatchEnvironment("IDM_URL", server.idmServer.URL.String())
		return s.Run(args...)
	}
}

type server struct {
	idmServer *idmtest.Server
	handler   *handler
}

func newServer(handler *handler) *server {
	srv := &server{
		idmServer: idmtest.NewServer(),
		handler:   handler,
	}
	for _, h := range identity.ReqServer.Handlers(srv.newHandler) {
		srv.idmServer.Router.Handle(h.Method, h.Path, h.Handle)
	}
	srv.idmServer.AddUser("admin@idm")
	return srv
}

func (srv *server) Close() {
	srv.idmServer.Close()
}

func (srv *server) adminAgent() admincmd.Agent {
	key := srv.idmServer.UserPublicKey("admin@idm")
	return admincmd.Agent{
		URL:        srv.idmServer.URL.String(),
		Username:   "admin@idm",
		PublicKey:  &key.Public,
		PrivateKey: &key.Private,
	}
}

func (srv *server) ThirdPartyInfo(context.Context, string) (bakery.ThirdPartyInfo, error) {
	return bakery.ThirdPartyInfo{
		PublicKey: srv.idmServer.Bakery.Oven.Key().Public,
		Version:   bakery.LatestVersion,
	}, nil
}

func (srv *server) newHandler(p httprequest.Params) (*handler, context.Context, error) {
	if err := srv.checkLogin(p.Context, p.Request); err != nil {
		return nil, nil, errgo.Mask(err, errgo.Any)
	}
	return srv.handler, p.Context, nil
}

type handler struct {
	modifyGroups func(*params.ModifyUserGroupsRequest) error
	queryUsers   func(*params.QueryUsersRequest) ([]string, error)
}

func (h *handler) ModifyGroups(req *params.ModifyUserGroupsRequest) error {
	return h.modifyGroups(req)
}

func (h *handler) QueryUsers(req *params.QueryUsersRequest) ([]string, error) {
	return h.queryUsers(req)
}

var ages = time.Now().Add(time.Hour)

func (srv *server) checkLogin(ctx context.Context, req *http.Request) error {
	_, authErr := srv.idmServer.Bakery.Checker.Auth(httpbakery.RequestMacaroons(req)...).Allow(context.TODO(), bakery.LoginOp)
	if authErr == nil {
		return nil
	}
	derr, ok := errgo.Cause(authErr).(*bakery.DischargeRequiredError)
	if !ok {
		return errgo.Mask(authErr)
	}
	version := httpbakery.RequestVersion(req)
	m, err := srv.idmServer.Bakery.Oven.NewMacaroon(ctx, version, ages, derr.Caveats, derr.Ops...)
	if err != nil {
		return errgo.Notef(err, "cannot create macaroon")
	}
	return httpbakery.NewDischargeRequiredErrorWithVersion(m, "", authErr, version)
}
