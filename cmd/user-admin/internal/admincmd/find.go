// Copyright 2016 Canonical Ltd.

package admincmd

import (
	"fmt"

	"github.com/juju/cmd"
	"gopkg.in/errgo.v1"
)

type findCommand struct {
	userCommand
}

func newFindCommand() cmd.Command {
	return &findCommand{}
}

var findDoc = `
The find command outputs the username associated with the specified user.

    user-admin find -e bob@example.com
`

func (c *findCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "find",
		Args:    c.args(),
		Purpose: "find a user",
		Doc:     findDoc,
	}
}

func (c *findCommand) Init(args []string) error {
	return errgo.Mask(c.userCommand.Init(nil))
}

func (c *findCommand) Run(ctxt *cmd.Context) error {
	username, err := c.lookupUser(ctxt)
	if err != nil {
		return errgo.Mask(err)
	}
	_, err = fmt.Fprintln(ctxt.Stdout, username)
	return errgo.Mask(err)
}
