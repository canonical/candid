// Copyright 2016 Canonical Ltd.

package admincmd

import (
	"github.com/juju/cmd"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
)

type removeGroupCommand struct {
	userCommand

	groups []string
}

func newRemoveGroupCommand() cmd.Command {
	return &removeGroupCommand{}
}

var removeGroupDoc = `
The remove-group command removes the specified user from the specified
group, or groups.

To remove the group-1 and group-2 groups from the user bob:
    user-admin remove-group -u bob group-1 group-2

To remove the example-1 and example-2 groups from the user with the
email removeress bob@example.com:
    user-admin remove-group -e bob@example.com group-1 group-2
`

func (c *removeGroupCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "remove-group",
		Args:    "[group...]",
		Purpose: "remove a user from groups",
		Doc:     removeGroupDoc,
	}
}

func (c *removeGroupCommand) Init(args []string) error {
	c.groups = args
	return errgo.Mask(c.userCommand.Init(nil))
}

func (c *removeGroupCommand) Run(ctxt *cmd.Context) error {
	username, err := c.lookupUser(ctxt)
	if err != nil {
		return errgo.Mask(err)
	}
	client, err := c.Client(ctxt)
	if err != nil {
		return errgo.Mask(err)
	}
	err = client.ModifyUserGroups(context.Background(), &params.ModifyUserGroupsRequest{
		Username: username,
		Groups: params.ModifyGroups{
			Remove: c.groups,
		},
	})
	return errgo.Mask(err)
}
