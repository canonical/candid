// Copyright 2016 Canonical Ltd.

package admincmd

import (
	"fmt"

	"github.com/juju/cmd"
	"github.com/juju/gnuflag"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
)

type createAdminAgentCommand struct {
	cmd.CommandBase
	url string
}

func newCreateAdminAgentCommand() cmd.Command {
	return &createAdminAgentCommand{}
}

var createAdminAgentDoc = `
The create-admin-agent command creates a new admin agent which can be
used when bootstrapping an identity server.

To create a new admin agent for a identity server on localhost use:
    user-admin create-admin-agent --idm-url http://localhost:8081

The generated output will be printed to standard output. It should be
saved into a file for future use.
`

func (c *createAdminAgentCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "create-admin-agent",
		Purpose: "create an admin agent",
		Doc:     createAdminAgentDoc,
	}
}

func (c *createAdminAgentCommand) SetFlags(f *gnuflag.FlagSet) {
	c.CommandBase.SetFlags(f)
	f.StringVar(&c.url, "idm-url", "", "URL of the identity server (defaults to $IDM_URL)")
}

func (c *createAdminAgentCommand) Run(ctxt *cmd.Context) error {
	kp, err := bakery.GenerateKey()
	if err != nil {
		return errgo.Mask(err)
	}
	a := Agent{
		URL:        idmURL(c.url),
		Username:   "admin@idm",
		PublicKey:  &kp.Public,
		PrivateKey: &kp.Private,
	}
	if err := Write(ctxt.GetStdout(), a); err != nil {
		return errgo.Mask(err)
	}
	fmt.Fprintln(ctxt.GetStdout(), "")
	return nil
}
