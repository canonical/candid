// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd

import (
	"context"

	"github.com/juju/cmd/v3"
	"gopkg.in/errgo.v1"

	"github.com/canonical/candid/params"
)

type clearMFACredentialsCommand struct {
	userCommand
}

func newClearMFACredentialsCommand(cc *candidCommand) cmd.Command {
	c := &clearMFACredentialsCommand{}
	c.candidCommand = cc
	return c
}

var clearMFACredentialsCommandDoc = `
The clear-mfa-credentials command removes all multi-factor authentication
credentials for the specified user.

    candid clear-mfa-credentials bob
`

func (c *clearMFACredentialsCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "clear-mfa-credentials",
		Args:    "username",
		Purpose: "clear MFA credentials",
		Doc:     clearMFACredentialsCommandDoc,
	}
}

func (c *clearMFACredentialsCommand) Init(args []string) error {
	if len(args) != 1 {
		return errgo.Newf("expected 1 argument, got %d", len(args))
	}
	c.username = args[0]
	return errgo.Mask(c.userCommand.Init(nil))
}

func (c *clearMFACredentialsCommand) Run(ctxt *cmd.Context) error {
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

	err = client.ClearUserMFACredentials(ctx,
		&params.ClearUserMFACredentialsRequest{
			Username: username,
		},
	)
	return errgo.Mask(err)
}
