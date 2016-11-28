// Copyright 2016 Canonical Ltd.

package admincmd_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"

	"github.com/juju/cmd"
	"github.com/juju/httprequest"
	"github.com/juju/idmclient/params"
	"github.com/juju/testing"
	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent"

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
// given handlers, creates a new 'admin.agent' file in s.Dir, set the
// IDM_URL environment variable to point to the newly created server and
// then runs the given ocmmand line. The command line is expected to
// contain the required flags to use the admin.agent file for login.
func (s *commandSuite) RunServer(c *gc.C, handlers []httprequest.Handler) func(args ...string) (code int, stdout, stderr string) {
	return func(args ...string) (code int, stdout, stderr string) {
		server := newServer(handlers)
		defer server.Close()
		ag := server.adminAgent()
		f, err := os.Create(filepath.Join(s.Dir, "admin.agent"))
		c.Assert(err, gc.Equals, nil)
		err = admincmd.Write(f, ag)
		c.Assert(err, gc.Equals, nil)
		s.PatchEnvironment("IDM_URL", server.server.URL)
		return s.Run(args...)
	}
}

type server struct {
	server        *httptest.Server
	bakery        *bakery.Service
	adminAgentKey *bakery.KeyPair

	loginUser string

	// mu protects the fields below it
	mu      sync.Mutex
	waits   map[string]chan struct{}
	infos   map[string]*bakery.ThirdPartyCaveatInfo
	results map[string]result
}

type result struct {
	caveats []checkers.Caveat
	error   error
}

func newServer(handlers []httprequest.Handler) *server {
	s := &server{
		waits:   make(map[string]chan struct{}),
		infos:   make(map[string]*bakery.ThirdPartyCaveatInfo),
		results: make(map[string]result),
	}

	r := httprouter.New()
	for _, h := range handlers {
		r.Handle(h.Method, h.Path, h.Handle)
	}
	var err error
	s.bakery, err = bakery.NewService(bakery.NewServiceParams{
		Locator: s,
	})
	if err != nil {
		panic(err)
	}
	r.GET("/login/:waitid", s.login)
	r.GET("/wait/:waitid", s.wait)
	d := httpbakery.NewDischargerFromService(s.bakery, httpbakery.ThirdPartyCheckerFunc(s.checkThirdPartyCaveat))
	for _, h := range d.Handlers() {
		r.Handle(h.Method, h.Path, h.Handle)
	}
	s.adminAgentKey, err = bakery.GenerateKey()
	if err != nil {
		panic(err)
	}
	s.server = httptest.NewServer(r)
	return s
}

// Close shuts down the server.
func (s *server) Close() {
	s.server.Close()
}

func (s *server) adminAgent() admincmd.Agent {
	return admincmd.Agent{
		URL:        s.server.URL,
		Username:   "admin@idm",
		PublicKey:  &s.adminAgentKey.Public,
		PrivateKey: &s.adminAgentKey.Private,
	}
}

func (s *server) checkThirdPartyCaveat(req *http.Request, info *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
	if info.Condition != "is-authenticated-user" {
		return nil, errgo.Newf("unknown third party caveat %q", info.Condition)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	waitid := fmt.Sprint(len(s.waits))
	ch := make(chan struct{})
	s.waits[waitid] = ch
	s.infos[waitid] = info
	return nil, &httpbakery.Error{
		Code: httpbakery.ErrInteractionRequired,
		Info: &httpbakery.ErrorInfo{
			VisitURL: fmt.Sprintf("%s/login/%s", s.server.URL, waitid),
			WaitURL:  fmt.Sprintf("%s/wait/%s", s.server.URL, waitid),
		},
	}
}

func (s *server) login(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	username, key, err := agent.LoginCookie(req)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == agent.ErrNoAgentLoginCookie && s.loginUser != "" {
		s.results[p.ByName("waitid")] = result{
			caveats: []checkers.Caveat{
				checkers.DeclaredCaveat("username", s.loginUser),
			},
		}
		close(s.waits[p.ByName("waitid")])
		fmt.Println("%s logged in", s.loginUser)
		return
	}
	if err != nil {
		s.results[p.ByName("waitid")] = result{
			error: err,
		}
		close(s.waits[p.ByName("waitid")])
		errorMapper.WriteError(w, err)
		return
	}
	s.agentLogin(w, req, p.ByName("waitid"), username, key)
}

func (s *server) agentLogin(w http.ResponseWriter, req *http.Request, waitid string, username string, key *bakery.PublicKey) {
	attrs, verr := httpbakery.CheckRequest(s.bakery, req, nil, checkers.New())
	if verr == nil {
		if attrs["username"] != username {
			err := errgo.Newf("macaroon username (%s) does not match cookie (%s)", attrs["username"], username)
			s.results[waitid] = result{
				error: err,
			}
			close(s.waits[waitid])
			errorMapper.WriteError(w, err)
			return
		}
		s.results[waitid] = result{
			caveats: []checkers.Caveat{
				checkers.DeclaredCaveat("username", username),
			},
		}
		close(s.waits[waitid])
		httprequest.WriteJSON(w, http.StatusOK, map[string]bool{"agent_login": true})
		return
	}
	version := httpbakery.RequestVersion(req)
	m, err := s.bakery.NewMacaroon(
		version,
		[]checkers.Caveat{
			checkers.DeclaredCaveat("username", username),
			bakery.LocalThirdPartyCaveat(key, version),
		},
	)
	if err != nil {
		panic(err)
	}
	httpbakery.WriteDischargeRequiredErrorForRequest(w, m, req.URL.Path, verr, req)
}

func (s *server) wait(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	s.mu.Lock()
	ch := s.waits[p.ByName("waitid")]
	s.mu.Unlock()
	<-ch
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.bakery.Discharge(bakery.ThirdPartyCheckerFunc(func(*bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
		r := s.results[p.ByName("waitid")]
		return r.caveats, r.error
	}), s.infos[p.ByName("waitid")].CaveatId)
	if err == nil {
		httprequest.WriteJSON(w, http.StatusOK, httpbakery.WaitResponse{
			Macaroon: m,
		})
		return
	}
	status, body := httpbakery.ErrorToResponse(err)
	httprequest.WriteJSON(w, status, body)
}

func (s *server) ThirdPartyInfo(_ string) (bakery.ThirdPartyInfo, error) {
	return bakery.ThirdPartyInfo{
		PublicKey: *s.bakery.PublicKey(),
		Version:   bakery.LatestVersion,
	}, nil
}

var errorMapper httprequest.ErrorMapper = httpbakery.ErrorToResponse

func modifyGroupsHandler(bakeryService *bakery.Service, f func(*params.ModifyUserGroupsRequest) error) httprequest.Handler {
	return errorMapper.Handle(func(p httprequest.Params, req *params.ModifyUserGroupsRequest) error {
		if err := checkLogin(bakeryService, p.Request); err != nil {
			return err
		}
		return f(req)
	})
}

func queryUsersHandler(bakeryService *bakery.Service, f func(*params.QueryUsersRequest) ([]string, error)) httprequest.Handler {
	return errorMapper.Handle(func(p httprequest.Params, req *params.QueryUsersRequest) ([]string, error) {
		if err := checkLogin(bakeryService, p.Request); err != nil {
			return nil, err
		}
		return f(req)
	})
}

func checkLogin(bakeryService *bakery.Service, req *http.Request) error {
	_, err := httpbakery.CheckRequest(bakeryService, req, nil, checkers.New())
	if err == nil {
		return nil
	}
	_, ok := errgo.Cause(err).(*bakery.VerificationError)
	if !ok {
		return err
	}
	version := httpbakery.RequestVersion(req)
	m, err := bakeryService.NewMacaroon(
		version,
		[]checkers.Caveat{{
			Location:  "http://" + req.Host,
			Condition: "is-authenticated-user",
		}},
	)
	if err != nil {
		return err
	}
	return httpbakery.NewDischargeRequiredErrorWithVersion(m, "", err, version)
}

func newBakery() *bakery.Service {
	loc := httpbakery.NewThirdPartyLocator(nil, nil)
	loc.AllowInsecure()
	bakeryService, err := bakery.NewService(bakery.NewServiceParams{
		Locator: loc,
	})
	if err != nil {
		panic(err)
	}
	return bakeryService
}
