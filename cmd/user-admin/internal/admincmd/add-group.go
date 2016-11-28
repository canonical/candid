// Copyright 2016 Canonical Ltd.

package admincmd

import (
	"github.com/juju/cmd"
	"github.com/juju/idmclient/params"
	"gopkg.in/errgo.v1"
)

type addGroupCommand struct {
	userCommand

	groups []string
}

func newAddGroupCommand() cmd.Command {
	return &addGroupCommand{}
}

var addGroupDoc = `
The add-group command adds the specified user to the specified group,
or groups.

To add the group-1 and group-2 groups to the user bob:
    user-admin add-group -u bob group-1 group-2

To add the group-1 and group-2 groups to the user with the email
address bob@example.com:
    user-admin add-group -e bob@example.com group-1 group-2
`

func (c *addGroupCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "add-group",
		Args:    c.args(),
		Purpose: "add a user to groups",
		Doc:     addGroupDoc,
	}
}

func (c *addGroupCommand) Init(args []string) error {
	c.groups = args
	return errgo.Mask(c.userCommand.Init(nil))
}

func (c *addGroupCommand) args() string {
	return c.userCommand.args() + " [group...]"
}

func (c *addGroupCommand) Run(ctxt *cmd.Context) error {
	username, err := c.lookupUser(ctxt)
	if err != nil {
		return errgo.Mask(err)
	}
	client, err := c.Client(ctxt)
	if err != nil {
		return errgo.Mask(err)
	}
	err = client.ModifyUserGroups(&params.ModifyUserGroupsRequest{
		Username: username,
		Groups: params.ModifyGroups{
			Add: c.groups,
		},
	})
	return errgo.Mask(err)
}
