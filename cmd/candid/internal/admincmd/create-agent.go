// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/juju/cmd/v3"
	"github.com/juju/gnuflag"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/canonical/candid/internal/auth"
	"github.com/canonical/candid/params"
)

type createAgentCommand struct {
	*candidCommand
	groups        []string
	agentFile     string
	agentFullName string
	admin         bool
	parent        bool
	publicKey     *bakery.PublicKey
}

func newCreateAgentCommand(c *candidCommand) cmd.Command {
	return &createAgentCommand{
		candidCommand: c,
	}
}

var createAgentDoc = `
The create-agent command creates an agent user on the Candid
server.

An agent user has an associated public key - the private key pair can
be used to authenticate as that agent.

The name of the agent is chosen by the identity manager itself
and is written to the agent file, except as a special case, if the
--admin flag is specified, when the agent information will only
be written locally (this is so that an admin agent file can be generated
before bootstrapping the Candid server for the first time).

The agent will be made a member of any of the specified groups as long
as the currently authenticated user is a member of those groups.

A new key will be generated unless a key is specified with the -k
flag or a key is found in the agent file (see below).

If the --agent-file flag is specified, the specified file will be updated with
the new agent information, otherwise the new agent information will be
printed to the standard output. Note when the -k flag is specified,
this information will be missing the private key.
`

func (c *createAgentCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "create-agent",
		Args:    "[group...]",
		Purpose: "create or update an agent user",
		Doc:     createAgentDoc,
	}
}

func (c *createAgentCommand) SetFlags(f *gnuflag.FlagSet) {
	c.candidCommand.SetFlags(f)
	publicKeyVar(f, &c.publicKey, "k", "public key of agent")
	publicKeyVar(f, &c.publicKey, "public-key", "")
	f.StringVar(&c.agentFile, "f", "", "agent file to update")
	f.StringVar(&c.agentFile, "agent-file", "", "")
	f.BoolVar(&c.admin, "admin", false, "generate an agent file for the admin user; does not contact the identity manager service")
	f.StringVar(&c.agentFullName, "name", "", "name of agent")
	f.BoolVar(&c.parent, "parent", false, "create a parent agent")
}

func (c *createAgentCommand) Init(args []string) error {
	c.groups = args
	if c.agentFile != "" && c.publicKey != nil {
		return errgo.Newf("cannot specify public key and an agent file")
	}
	return errgo.Mask(c.candidCommand.Init(nil))
}

func (c *createAgentCommand) Run(cmdctx *cmd.Context) error {
	defer c.Close(cmdctx)
	ctx := context.Background()
	client, err := c.Client(cmdctx)
	if err != nil {
		return errgo.Mask(err)
	}
	var key *bakery.KeyPair
	var agents *agent.AuthInfo
	if c.agentFile != "" {
		agents, err = readAgentFile(cmdctx.AbsPath(c.agentFile))
		if err != nil {
			if !os.IsNotExist(errgo.Cause(err)) {
				return errgo.Mask(err)
			}
			agents = new(agent.AuthInfo)
		} else {
			key = agents.Key
		}
	}
	switch {
	case key == nil && c.publicKey == nil:
		key1, err := bakery.GenerateKey()
		if err != nil {
			return errgo.Notef(err, "cannot generate key")
		}
		key = key1
		c.publicKey = &key.Public
	case c.publicKey == nil:
		c.publicKey = &key.Public
	}
	var username params.Username
	if c.admin {
		username = auth.AdminUsername
		if len(c.groups) > 0 {
			return errgo.Newf("cannot specify groups when using --admin flag")
		}
	} else {
		resp, err := client.CreateAgent(ctx, &params.CreateAgentRequest{
			CreateAgentBody: params.CreateAgentBody{
				FullName:   c.agentFullName,
				Groups:     c.groups,
				PublicKeys: []*bakery.PublicKey{c.publicKey},
				Parent:     c.parent,
			},
		})
		if err != nil {
			return errgo.Mask(err)
		}
		username = resp.Username
	}
	if agents != nil {
		if agents.Key == nil {
			agents.Key = key
		}
		agents.Agents = append(agents.Agents, agent.Agent{
			URL:      client.Client.BaseURL,
			Username: string(username),
		})
		if err := writeAgentFile(cmdctx.AbsPath(c.agentFile), agents); err != nil {
			return errgo.Mask(err)
		}
		fmt.Fprintf(cmdctx.Stdout, "added agent %s for %s to %s\n", username, client.Client.BaseURL, c.agentFile)
		return nil
	}
	agentsData := &agent.AuthInfo{
		Agents: []agent.Agent{{
			URL:      client.Client.BaseURL,
			Username: string(username),
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
