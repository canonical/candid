// Copyright 2016 Canonical Ltd.

package admincmd

import (
	"time"

	"github.com/juju/cmd"
	"github.com/juju/gnuflag"
	"github.com/juju/idmclient/params"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
)

type findCommand struct {
	idmCommand

	out cmd.Output

	email             string
	lastLoginDays     uint
	lastDischargeDays uint
}

func newFindCommand() cmd.Command {
	return &findCommand{}
}

var findDoc = `
The find command finds users that match the request parameters.

    user-admin find -e bob@example.com
    user-admin find --last-login=30
`

func (c *findCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "find",
		Purpose: "find users",
		Doc:     findDoc,
	}
}

func (c *findCommand) SetFlags(f *gnuflag.FlagSet) {
	c.idmCommand.SetFlags(f)

	c.out.AddFlags(f, "smart", cmd.DefaultFormatters)

	f.StringVar(&c.email, "e", "", "email address of the user")
	f.StringVar(&c.email, "email", "", "")
	f.UintVar(&c.lastLoginDays, "last-login", 0, "users whose last successful login was within this number of days")
	f.UintVar(&c.lastDischargeDays, "last-discharge", 0, "users whose last successful discharge was within this number of days")
}

func (c *findCommand) Init(args []string) error {
	return errgo.Mask(c.idmCommand.Init(nil))
}

func (c *findCommand) Run(ctxt *cmd.Context) error {
	client, err := c.idmCommand.Client(ctxt)
	if err != nil {
		return errgo.Mask(err)
	}
	req := params.QueryUsersRequest{
		Email: c.email,
	}
	if c.lastLoginDays > 0 {
		req.LastLoginSince = daysAgo(c.lastLoginDays)
	}
	if c.lastDischargeDays > 0 {
		req.LastDischargeSince = daysAgo(c.lastDischargeDays)
	}
	usernames, err := client.QueryUsers(context.Background(), &req)
	if err != nil {
		return errgo.Mask(err)
	}
	return c.out.Write(ctxt, usernames)
}

// daysAgo returns the current time less the given
// number of days, formatted as a string as required
// by time fields in params.QueryUsersRequest.
func daysAgo(days uint) string {
	t := time.Now().AddDate(0, 0, -int(days))
	b, err := t.MarshalText()
	if err != nil {
		// This should be impossible unless things are severly wrong.
		panic(err)
	}
	return string(b)
}
