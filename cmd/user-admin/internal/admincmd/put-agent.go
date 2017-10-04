// Copyright 2017 Canonical Ltd.

package admincmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/juju/cmd"
	"github.com/juju/idmclient"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"

	"github.com/juju/gnuflag"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent"
)

type putAgentCommand struct {
	idmCommand
	agentName string
	groups    []string
	agentFile string
	noPut     bool
	publicKey *bakery.PublicKey
}

func newPutAgentCommand() cmd.Command {
	return &putAgentCommand{}
}

var putAgentDoc = `
The put-agent command creates or updates an agent user.

An agent user has an associated public key - the private key pair can
be used to authenticate as that agent.

The agent user name is of the form $agentname@$username where $agentname
is a name chosen for the agent and $username is the user that "owns" the
agent. If the specified agent name does not contain any @ characters,
the currently authenticated user will be used for $username.

The agent will be made a member of any of the specified groups as long
as the currently authenticated user is a member of those groups.

If a key is not specified with the -k flag, a new key will be generated
unless one is found from the agent file (see below).

If the --agent-file flag is specified, the specified file will be updated with
the new agent information, otherwise the new agent information will be
printed to the standard output. Note when the -k flag is specified,
this information will be missing the private key.
`

func (c *putAgentCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "put-agent",
		Args:    "agent-username [group...]",
		Purpose: "create or update an agent user",
		Doc:     putAgentDoc,
	}
}

func (c *putAgentCommand) SetFlags(f *gnuflag.FlagSet) {
	c.idmCommand.SetFlags(f)
	publicKeyVar(f, &c.publicKey, "k", "public key of agent")
	publicKeyVar(f, &c.publicKey, "public-key", "")
	f.StringVar(&c.agentFile, "f", "", "agent file to update")
	f.StringVar(&c.agentFile, "agent-file", "", "")
	f.BoolVar(&c.noPut, "n", false, "do not actually create the agent on the identity manager")
}

func (c *putAgentCommand) Init(args []string) error {
	if len(args) < 1 {
		return errgo.Newf("missing agent username argument")
	}
	c.agentName = args[0]
	c.groups = args[1:]
	if c.agentFile != "" && c.publicKey != nil {
		return errgo.Newf("cannot specify public key and an agent file")
	}
	return errgo.Mask(c.idmCommand.Init(nil))
}

func (c *putAgentCommand) Run(cmdctx *cmd.Context) error {
	ctx := context.Background()
	client, err := c.Client(cmdctx)
	if err != nil {
		return errgo.Mask(err)
	}
	agentName, owner, err := inferAgentName(ctx, client, c.agentName)
	if err != nil {
		return errgo.Mask(err)
	}
	var key *bakery.KeyPair
	var agents *agent.AuthInfo
	if c.agentFile != "" {
		agents, err = readAgentFile(c.agentFile)
		if err != nil {
			if !os.IsNotExist(errgo.Cause(err)) {
				return errgo.Mask(err)
			}
			agents = new(agent.AuthInfo)
		} else {
			key = agents.Key
		}
	}
	if key == nil && c.publicKey == nil {
		key1, err := bakery.GenerateKey()
		if err != nil {
			return errgo.Notef(err, "cannot generate key")
		}
		key = key1
		c.publicKey = &key.Public
	}
	if !c.noPut {
		if err := client.SetUser(ctx, &params.SetUserRequest{
			Username: agentName,
			User: params.User{
				Owner:      owner,
				IDPGroups:  c.groups,
				PublicKeys: []*bakery.PublicKey{c.publicKey},
			},
		}); err != nil {
			return errgo.Mask(err)
		}
	}
	if agents != nil {
		if agents.Key == nil {
			agents.Key = key
		}
		agents.Agents = append(agents.Agents, agent.Agent{
			URL:      client.Client.BaseURL,
			Username: string(agentName),
		})

		if err := writeAgentFile(c.agentFile, agents); err != nil {
			return errgo.Mask(err)
		}
		fmt.Fprintf(cmdctx.Stdout, "updated agent %s for %s in %s\n", agentName, client.Client.BaseURL, c.agentFile)
		return nil
	}
	agentsData := &agent.AuthInfo{
		Agents: []agent.Agent{{
			URL:      client.Client.BaseURL,
			Username: string(agentName),
		}},
	}
	if key != nil {
		agentsData.Key = key
	} else {
		agentsData.Key = &bakery.KeyPair{
			Public: *c.publicKey,
		}
	}
	data, err := json.MarshalIndent(agentsData, "", "\t")
	if err != nil {
		return errgo.Mask(err)
	}
	data = append(data, '\n')
	cmdctx.Stdout.Write(data)
	return nil
}

// inferAgentName infers the agent name if it's not already fully specified,
// and returns the inferred name and the agent's owner.
func inferAgentName(ctx context.Context, client *idmclient.Client, agentName0 string) (agentName, owner params.Username, err error) {
	agentName = params.Username(agentName0)
	if i := strings.Index(string(agentName), "@"); i >= 0 {
		return agentName, agentName[i+1:], nil
	}
	r, err := client.WhoAmI(ctx, &params.WhoAmIRequest{})
	if err != nil {
		return "", "", errgo.Notef(err, "cannot retrieve current user name")
	}
	owner = params.Username(r.User)
	return agentName + "@" + owner, owner, nil
}
