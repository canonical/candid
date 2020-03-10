// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/juju/cmd"
	"github.com/juju/gnuflag"
	"github.com/juju/persistent-cookiejar"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/CanonicalLtd/candidclient.v1"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/canonical/candid/version"
)

// jujuLoggingConfigEnvKey matches osenv.JujuLoggingConfigEnvKey
// in the Juju project.
const jujuLoggingConfigEnvKey = "JUJU_LOGGING_CONFIG"

var cmdDoc = `
Manage the users on an identity server. By default the identity server
at https://api.jujucharms.com/identity will be modified. This can be
overridden either by setting the CANDID_URL environment variable, or by
setting the --candid-url command line parameter.

To use agent credentials for Candid operations, use the --agent flag
or specify the BAKERY_AGENT_FILE environment variable, both of which
hold the path to a file containing agent credentials in JSON format
(see the create-agent subcommand for details).

To configure additional CA certificates for the client an environment
variable CANDID_CA_CERTS can be used. This contains a colon separated list
of files which should each contain a list of PEM encoded certificates. All
of these certificates will be added to the certificates from the system
pool. Any file in the list which cannot be found, or cannot be read by
the current user will be silently skipped.
`

func New() cmd.Command {
	c := new(candidCommand)
	supercmd := cmd.NewSuperCommand(cmd.SuperCommandParams{
		Name:    "candid",
		Doc:     cmdDoc,
		Purpose: "manage users on an identity server",
		Log: &cmd.Log{
			DefaultConfig: os.Getenv(jujuLoggingConfigEnvKey),
		},
		GlobalFlags: c,
		Version:     version.VersionInfo.Version,
	})
	supercmd.Register(newACLCommand(c))
	supercmd.Register(newAddGroupCommand(c))
	supercmd.Register(newCreateAgentCommand(c))
	supercmd.Register(newFindCommand(c))
	supercmd.Register(newRemoveGroupCommand(c))
	supercmd.Register(newShowCommand(c))
	return supercmd
}

// candidCommand is a cmd.Command that provides a client for communicating
// with an identity manager. The identity manager can be sepcified via
// the command line, or using the CANDID_URL environment variable.
type candidCommand struct {
	cmd.CommandBase

	url       string
	agentFile string

	// mu protects the fields below it.
	mu           sync.Mutex
	bakeryClient *httpbakery.Client
	client       *candidclient.Client
	jar          *cookiejar.Jar
}

// Close must be called at the end of a command's Run to ensure that
// cookies are saved.
func (c *candidCommand) Close(ctxt *cmd.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jar == nil {
		return
	}
	if err := c.jar.Save(); err != nil {
		fmt.Fprintf(ctxt.Stderr, "cannot save cookies: %v", err)
	}
	c.jar = nil
}

// AddFlags implements cmd.FlagAdder to add global flags
// to the flag set.
func (c *candidCommand) AddFlags(f *gnuflag.FlagSet) {
	f.StringVar(&c.url, "candid-url", "", "URL of the identity server (defaults to $CANDID_URL)")
	f.StringVar(&c.agentFile, "a", "", "name of file containing agent login details")
	f.StringVar(&c.agentFile, "agent", "", "")
}

// BakeryClient creates a new httpbakery.Client using the parameters specified
// in the flags and environment.
func (c *candidCommand) BakeryClient(ctxt *cmd.Context) (*httpbakery.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bakeryClientLocked(ctxt)
}

// bakeryClientLocked creates a new httpbakery.Client using the parameters specified
// in the flags and environment. bakeryClient must be called with the mutex locked.
func (c *candidCommand) bakeryClientLocked(ctxt *cmd.Context) (*httpbakery.Client, error) {
	if c.bakeryClient != nil {
		return c.bakeryClient, nil
	}
	bClient := httpbakery.NewClient()
	var authInfo *agent.AuthInfo
	if c.agentFile != "" {
		ai, err := readAgentFile(ctxt.AbsPath(c.agentFile))
		if err != nil {
			return nil, errgo.Notef(err, "cannot load agent information")
		}
		authInfo = ai
	} else if ai, err := agent.AuthInfoFromEnvironment(); err == nil {
		authInfo = ai
	} else if errgo.Cause(err) != agent.ErrNoAuthInfo {
		return nil, errgo.Mask(err)
	}
	if authInfo != nil {
		// Agent authentication has been specified, so we probably don't
		// want to use existing cookies (which might be logged in as a different
		// user) or to fall back to interactive authentication.
		agent.SetUpAuth(bClient, authInfo)
	} else {
		jar, err := cookiejar.New(&cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		})
		if err != nil {
			return nil, errgo.Mask(err)
		}
		c.jar = jar
		bClient.Client.Jar = jar
		bClient.AddInteractor(httpbakery.WebBrowserInteractor{})
	}
	if err := c.loadCACerts(bClient.Client); err != nil {
		return nil, errgo.Mask(err)
	}
	c.bakeryClient = bClient
	return bClient, nil
}

// loadCACerts loads any certificates found in the files specified by
// CANDID_CA_CERTS, if any, and adds them to the system CA certificates
// for this client.
func (c *candidCommand) loadCACerts(client *http.Client) error {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return errgo.Notef(err, "cannot load system CA certificates")
	}
	for _, fn := range filepath.SplitList(os.Getenv("CANDID_CA_CERTS")) {
		buf, err := ioutil.ReadFile(fn)
		if os.IsNotExist(err) || os.IsPermission(err) {
			// If the file doesn't exist, or is not readable
			// ignore it. This allows the environment
			// variable to be set with potential paths even
			// when there are no certificates to load.
			continue
		}
		if err != nil {
			return errgo.Notef(err, "cannot load CA certificates")
		}
		certPool.AppendCertsFromPEM(buf)
	}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}
	return nil
}

// Client creates a new candidclient.Client using the parameters specified
// in the flags and environment.
func (c *candidCommand) Client(ctxt *cmd.Context) (*candidclient.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	bClient, err := c.bakeryClientLocked(ctxt)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	candidURL := candidURL(c.url)
	client, err := candidclient.New(candidclient.NewParams{
		BaseURL: candidURL,
		Client:  bClient,
	})
	if err != nil {
		return nil, errgo.Mask(err)
	}
	c.client = client
	return client, nil
}

func candidURL(url string) string {
	if url != "" {
		return url
	}
	if url := os.Getenv("CANDID_URL"); url != "" {
		return url
	}
	return candidclient.Production
}

// usercmd is a cmd.Command that provides the ability to lookup and
// manipulate a user that is specified on the command line either by
// username or email address. Commands which wish to perform operations
// on a particular user should embed this type and use lookupUser to find
// the username to use in the subsequent requests.
type userCommand struct {
	*candidCommand

	username string
	email    string
}

func (c *userCommand) SetFlags(f *gnuflag.FlagSet) {
	c.candidCommand.SetFlags(f)

	f.StringVar(&c.username, "u", "", "username of the user")
	f.StringVar(&c.username, "username", "", "")
	f.StringVar(&c.email, "e", "", "email address of the user")
	f.StringVar(&c.email, "email", "", "")
}

func (c *userCommand) Init(args []string) error {
	if c.username == "" && c.email == "" {
		return errgo.New("no user specified, please specify either username or email")
	} else if c.username != "" && c.email != "" {
		return errgo.New("both username and email specified, please specify either username or email")
	}
	return errgo.Mask(c.candidCommand.Init(args))
}

// AllowInterspersedFlags implements cmd.Command.AllowInterspersedFlags,
// by making them not allowed.
func (c *userCommand) AllowInterspersedFlags() bool {
	return false
}

// lookupUser returns the username specified by the command line flags.
func (c *userCommand) lookupUser(ctxt *cmd.Context) (params.Username, error) {
	if c.username != "" {
		return params.Username(c.username), nil
	}
	client, err := c.Client(ctxt)
	if err != nil {
		return "", errgo.Mask(err)
	}
	users, err := client.QueryUsers(context.Background(), &params.QueryUsersRequest{
		Email: c.email,
	})
	if err != nil {
		return "", errgo.Mask(err)
	}
	switch len(users) {
	case 0:
		return "", errgo.Newf("no user found for email %q", c.email)
	case 1:
		return params.Username(users[0]), nil
	}
	// Note: it is expected that for the most part this situation
	// should not come up as an identity server will not have many
	// identity providers and it is expected that they will not allow
	// more than one user to be registered with a unique email
	// address. There are however some situations in which this will
	// be possible. One case is when the user is a jujucharms.com
	// user and a snappy user which the identity server will keep
	// separate for implementation reasons, but could represent the
	// same Ubuntu SSO user.
	return "", errgo.Newf("more than one user found with email %q (%s)", c.email, strings.Join(users, ", "))
}

func publicKeyVar(f *gnuflag.FlagSet, key **bakery.PublicKey, name string, usage string) {
	f.Var(publicKeyValue{key}, name, usage)
}

type publicKeyValue struct {
	key **bakery.PublicKey
}

// Set implements gnuflag.Getter.Set.
func (v publicKeyValue) Set(s string) error {
	var k bakery.PublicKey
	if err := k.UnmarshalText([]byte(s)); err != nil {
		return errgo.Mask(err)
	}
	*v.key = &k
	return nil
}

// String implements gnuflag.Getter.String.
func (v publicKeyValue) String() string {
	if *v.key == nil {
		return `""`
	}
	// Marshaling a key can never fail (and even
	// if it could, there's no way of returning an error here)
	data, _ := (*v.key).MarshalText()
	return fmt.Sprintf("%q", data)
}

// Get implements gnuflag.Getter.Get.
func (v publicKeyValue) Get() interface{} {
	return *v.key
}

func readAgentFile(f string) (*agent.AuthInfo, error) {
	data, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, errgo.Mask(err, os.IsNotExist)
	}
	var v agent.AuthInfo
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, errgo.Notef(err, "cannot parse agent data from %q", f)
	}
	return &v, nil
}

func writeAgentFile(f string, v *agent.AuthInfo) error {
	data, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		return errgo.Mask(err)
	}
	data = append(data, '\n')
	// TODO should we write this atomically?
	if err := ioutil.WriteFile(f, data, 0600); err != nil {
		return errgo.Mask(err)
	}
	return nil
}
