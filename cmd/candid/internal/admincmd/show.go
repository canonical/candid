// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd

import (
	"context"
	"time"

	"github.com/juju/cmd/v3"
	"github.com/juju/gnuflag"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v3/bakery"

	"github.com/canonical/candid/params"
)

type showCommand struct {
	userCommand

	out cmd.Output
}

func newShowCommand(cc *candidCommand) cmd.Command {
	c := &showCommand{}
	c.candidCommand = cc
	return c
}

var showDoc = `
The show command shows the details for the specified user.

    candid show -e bob@example.com
`

func (c *showCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "show",
		Purpose: "show user details",
		Doc:     showDoc,
	}
}

func (c *showCommand) SetFlags(f *gnuflag.FlagSet) {
	c.userCommand.SetFlags(f)

	c.out.AddFlags(f, "smart", cmd.DefaultFormatters.Formatters())
}

func (c *showCommand) Run(ctxt *cmd.Context) error {
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
	u, err := client.User(ctx, &params.UserRequest{
		Username: username,
	})
	if err != nil {
		return errgo.Mask(err)
	}
	user := user{
		Username:      string(u.Username),
		ExternalID:    u.ExternalID,
		Owner:         string(u.Owner),
		Groups:        []string{},
		SSHKeys:       []string{},
		LastLogin:     timeString(u.LastLogin),
		LastDischarge: timeString(u.LastDischarge),
	}
	if u.ExternalID != "" {
		user.Name = &u.FullName
		user.Email = &u.Email
	} else {
		user.PublicKeys = u.PublicKeys
	}
	if len(u.IDPGroups) > 0 {
		user.Groups = u.IDPGroups
	}
	if len(u.SSHKeys) > 0 {
		user.SSHKeys = u.SSHKeys
	}
	return c.out.Write(ctxt, user)
}

func timeString(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	return t.Format(time.RFC3339)
}

// user represents a user in the system.
type user struct {
	Username      string              `json:"username" yaml:"username"`
	ExternalID    string              `json:"external-id,omitempty" yaml:"external-id,omitempty"`
	Name          *string             `json:"name,omitempty" yaml:"name,omitempty"`
	Email         *string             `json:"email,omitempty" yaml:"email,omitempty"`
	Owner         string              `json:"owner,omitempty" yaml:"owner,omitempty"`
	PublicKeys    []*bakery.PublicKey `json:"public-keys,omitempty" yaml:"public-keys,omitempty"`
	Groups        []string            `json:"groups" yaml:"groups"`
	SSHKeys       []string            `json:"ssh-keys" yaml:"ssh-keys"`
	LastLogin     string              `json:"last-login" yaml:"last-login"`
	LastDischarge string              `json:"last-discharge" yaml:"last-discharge"`
}
