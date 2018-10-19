// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd

import (
	"github.com/juju/aclstore/aclclient"
	"github.com/juju/cmd"
	"github.com/juju/gnuflag"
	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
)

var aclCmdDoc = `
The acl command is used to manage ACLs.
`

func newACLCommand(cc *candidCommand) cmd.Command {
	supercmd := cmd.NewSuperCommand(cmd.SuperCommandParams{
		Name:    "acl",
		Doc:     aclCmdDoc,
		Purpose: "manage candid ACLs",
	})

	supercmd.Register(&aclGrantCommand{candidCommand: cc})
	supercmd.Register(&aclRevokeCommand{candidCommand: cc})
	supercmd.Register(&aclShowCommand{candidCommand: cc})

	return supercmd
}

var aclShowDoc = `
The show command shows the members of the specified ACL.

    candid acl show read-user
`

type aclShowCommand struct {
	*candidCommand
	name string
	out  cmd.Output
}

func (c *aclShowCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "show",
		Purpose: "show acl members",
		Doc:     aclShowDoc,
	}
}

func (c *aclShowCommand) SetFlags(f *gnuflag.FlagSet) {
	c.candidCommand.SetFlags(f)
	c.out.AddFlags(f, "smart", cmd.DefaultFormatters)
}

func (c *aclShowCommand) Init(args []string) error {
	if err := c.candidCommand.Init(nil); err != nil {
		return errgo.Mask(err)
	}
	if len(args) < 1 {
		return errgo.New("ACL name required")
	}
	if len(args) > 1 {
		return errgo.New("only one ACL may be specified")
	}
	c.name = args[0]
	return nil
}

func (c *aclShowCommand) Run(ctxt *cmd.Context) error {
	defer c.Close(ctxt)
	client, err := aclClient(ctxt, c.candidCommand)
	if err != nil {
		return errgo.Mask(err)
	}
	ctx := context.Background()
	acl, err := client.Get(ctx, c.name)
	if err != nil {
		return errgo.Mask(err)
	}
	return errgo.Mask(c.out.Write(ctxt, acl))
}

var aclGrantDoc = `
The grant command adds users to the specified ACL.

    candid acl grant read-user alice bob
`

type aclGrantCommand struct {
	*candidCommand
	name  string
	users []string
}

func (c *aclGrantCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "grant",
		Purpose: "add users to an ACL",
		Doc:     aclGrantDoc,
	}
}

func (c *aclGrantCommand) Init(args []string) error {
	if err := c.candidCommand.Init(nil); err != nil {
		return errgo.Mask(err)
	}
	if len(args) < 2 {
		return errgo.New("ACL name and at least one user required")
	}
	c.name = args[0]
	c.users = args[1:]
	return nil
}

func (c *aclGrantCommand) Run(ctxt *cmd.Context) error {
	defer c.Close(ctxt)
	client, err := aclClient(ctxt, c.candidCommand)
	if err != nil {
		return errgo.Mask(err)
	}
	return errgo.Mask(client.Add(context.Background(), c.name, c.users))
}

var aclRevokeDoc = `
The revoke command removes users from the specified ACL.

    candid acl revoke read-user alice bob
`

type aclRevokeCommand struct {
	*candidCommand
	name  string
	users []string
}

func (c *aclRevokeCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "revoke",
		Purpose: "remove users from an ACL",
		Doc:     aclRevokeDoc,
	}
}

func (c *aclRevokeCommand) Init(args []string) error {
	if err := c.candidCommand.Init(nil); err != nil {
		return errgo.Mask(err)
	}
	if len(args) < 2 {
		return errgo.New("ACL name and at least one user required")
	}
	c.name = args[0]
	c.users = args[1:]
	return nil
}

func (c *aclRevokeCommand) Run(ctxt *cmd.Context) error {
	defer c.Close(ctxt)
	client, err := aclClient(ctxt, c.candidCommand)
	if err != nil {
		return errgo.Mask(err)
	}
	return errgo.Mask(client.Remove(context.Background(), c.name, c.users))
}

func aclClient(ctxt *cmd.Context, c *candidCommand) (*aclclient.Client, error) {
	bClient, err := c.BakeryClient(ctxt)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return aclclient.New(aclclient.NewParams{
		BaseURL: candidURL(c.url) + "/acls",
		Doer:    bClient,
	}), nil
}
