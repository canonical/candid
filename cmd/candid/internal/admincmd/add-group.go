// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd

import (
	"context"

	"github.com/juju/cmd"
	"gopkg.in/errgo.v1"

	"github.com/canonical/candid/params"
)

type addGroupCommand struct {
	userCommand

	groups []string
}

func newAddGroupCommand(cc *candidCommand) cmd.Command {
	c := &addGroupCommand{}
	c.candidCommand = cc
	return c
}

var addGroupDoc = `
The add-group command adds the specified user to the specified group,
or groups.

To add the group-1 and group-2 groups to the user bob:
    candid add-group -u bob group-1 group-2

To add the group-1 and group-2 groups to the user with the email
address bob@example.com:
    candid add-group -e bob@example.com group-1 group-2
`

func (c *addGroupCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "add-group",
		Args:    "[group...]",
		Purpose: "add a user to groups",
		Doc:     addGroupDoc,
	}
}

func (c *addGroupCommand) Init(args []string) error {
	c.groups = args
	return errgo.Mask(c.userCommand.Init(nil))
}

func (c *addGroupCommand) Run(ctxt *cmd.Context) error {
	defer c.Close(ctxt)
	ctx := context.Background()
	username, err := c.lookupUser(ctxt)
	if err != nil {
		return errgo.Mask(err)
	}
	client, err := c.Client(ctxt)
	if err != nil {
		return errgo.Mask(err)
	}
	err = client.ModifyUserGroups(ctx, &params.ModifyUserGroupsRequest{
		Username: username,
		Groups: params.ModifyGroups{
			Add: c.groups,
		},
	})
	return errgo.Mask(err)
}
