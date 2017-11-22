// Copyright 2016 Canonical Ltd.

package admincmd_test

import (
	"bytes"
	"net/http"
	"path/filepath"

	"github.com/juju/cmd"
	"github.com/juju/testing"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/juju/idmclient.v1/params"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/blues-identity/cmd/user-admin/internal/admincmd"
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
		server := newServer(c, handler)
		defer server.Close()
		ag := server.adminAgent()
		err := admincmd.WriteAgentFile(filepath.Join(s.Dir, "admin.agent"), ag)
		c.Assert(err, gc.Equals, nil)
		s.PatchEnvironment("IDM_URL", server.Location())
		return s.Run(args...)
	}
}

type server struct {
	*AgentDischarger
	bakery   *identchecker.Bakery
	adminKey *bakery.KeyPair
	handler  *handler
}

func newServer(c *gc.C, handler *handler) *server {
	adminKey, err := bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
	srv := &server{
		AgentDischarger: NewAgentDischarger(),
		adminKey:        adminKey,
		handler:         handler,
	}
	reqsrv := httprequest.Server{
		ErrorMapper: httpbakery.ErrorToResponse,
	}
	bakeryKey, err := bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
	srv.bakery = identchecker.NewBakery(identchecker.BakeryParams{
		Key:            bakeryKey,
		Locator:        srv,
		IdentityClient: IdentityClient(srv.Location()),
	})
	srv.AgentDischarger.Discharger.AddHTTPHandlers(reqsrv.Handlers(srv.newHandler))
	return srv
}

// adminAgent returns an agent Visitor holding
// details of the admin agent.
func (srv *server) adminAgent() *agent.AuthInfo {
	return &agent.AuthInfo{
		Key: srv.adminKey,
		Agents: []agent.Agent{{
			URL:      srv.Location(),
			Username: "admin@idm",
		}},
	}
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
	setUser      func(*params.SetUserRequest) error
	user         func(*params.UserRequest) (*params.User, error)
	whoAmI       func(*params.WhoAmIRequest) (*params.WhoAmIResponse, error)
}

func (h *handler) ModifyGroups(req *params.ModifyUserGroupsRequest) error {
	return h.modifyGroups(req)
}

func (h *handler) QueryUsers(req *params.QueryUsersRequest) ([]string, error) {
	return h.queryUsers(req)
}

func (h *handler) SetUser(req *params.SetUserRequest) error {
	return h.setUser(req)
}

func (h *handler) User(req *params.UserRequest) (*params.User, error) {
	return h.user(req)
}

func (h *handler) WhoAmI(p *params.WhoAmIRequest) (*params.WhoAmIResponse, error) {
	return h.whoAmI(p)
}

func (srv *server) checkLogin(ctx context.Context, req *http.Request) error {
	_, authErr := srv.bakery.Checker.Auth(httpbakery.RequestMacaroons(req)...).Allow(context.TODO(), identchecker.LoginOp)
	derr, ok := errgo.Cause(authErr).(*bakery.DischargeRequiredError)
	if !ok {
		return errgo.Mask(authErr)
	}
	version := httpbakery.RequestVersion(req)
	m, err := srv.bakery.Oven.NewMacaroon(ctx, version, derr.Caveats, derr.Ops...)
	if err != nil {
		return errgo.Notef(err, "cannot create macaroon")
	}
	return httpbakery.NewDischargeRequiredError(httpbakery.DischargeRequiredErrorParams{
		Macaroon:      m,
		OriginalError: authErr,
		Request:       req,
	})
}
