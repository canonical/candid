// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/juju/cmd"
	"github.com/juju/gnuflag"
	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/CanonicalLtd/candid/internal/auth"
)

type putAgentCommand struct {
	candidCommand
	groups        []string
	agentFile     string
	agentFullName string
	admin         bool
	publicKey     *bakery.PublicKey
}

func newPutAgentCommand() cmd.Command {
	return &putAgentCommand{}
}

var putAgentDoc = `
The put-agent command creates or updates an agent user.

An agent user has an associated public key - the private key pair can
be used to authenticate as that agent.

The name of the agent is chosen by the identity manager itself
and is written to the agent file.

The agent will be made a member of any of the specified groups as long
as the currently authenticated user is a member of those groups.

A new key will be generated unless a key is specified with the -k
flag or a key is found in the agent file (see below).

If the --agent-file flag is specified, the specified file will be updated with
the new agent information, otherwise the new agent information will be
printed to the standard output. Note when the -k flag is specified,
this information will be missing the private key.
`

func (c *putAgentCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "put-agent",
		Args:    "[group...]",
		Purpose: "create or update an agent user",
		Doc:     putAgentDoc,
	}
}

func (c *putAgentCommand) SetFlags(f *gnuflag.FlagSet) {
	c.candidCommand.SetFlags(f)
	publicKeyVar(f, &c.publicKey, "k", "public key of agent")
	publicKeyVar(f, &c.publicKey, "public-key", "")
	f.StringVar(&c.agentFile, "f", "", "agent file to update")
	f.StringVar(&c.agentFile, "agent-file", "", "")
	f.BoolVar(&c.admin, "admin", false, "generate an agent file for the admin user; does not contact the identity manager service")
	f.StringVar(&c.agentFullName, "name", "", "name of agent")
}

func (c *putAgentCommand) Init(args []string) error {
	c.groups = args
	if c.agentFile != "" && c.publicKey != nil {
		return errgo.Newf("cannot specify public key and an agent file")
	}
	return errgo.Mask(c.candidCommand.Init(nil))
}

func (c *putAgentCommand) Run(cmdctx *cmd.Context) error {
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
	} else {
		resp, err := client.CreateAgent(ctx, &params.CreateAgentRequest{
			CreateAgentBody: params.CreateAgentBody{
				FullName:   c.agentFullName,
				Groups:     c.groups,
				PublicKeys: []*bakery.PublicKey{c.publicKey},
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
