// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package admincmd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/juju/cmd"
	"github.com/juju/gnuflag"
	"golang.org/x/net/context"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/errgo.v1"
)

type findCommand struct {
	*candidCommand

	out cmd.Output

	detail            string
	email             string
	lastLoginDays     uint
	lastDischargeDays uint
}

func newFindCommand(c *candidCommand) cmd.Command {
	return &findCommand{
		candidCommand: c,
	}
}

var findDoc = `
The find command finds users that match the request parameters.

    candid find -e bob@example.com
    candid find --last-login=30
`

func (c *findCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "find",
		Purpose: "find users",
		Doc:     findDoc,
	}
}

func (c *findCommand) SetFlags(f *gnuflag.FlagSet) {
	c.candidCommand.SetFlags(f)

	c.out.AddFlags(f, "tab", map[string]cmd.Formatter{
		"yaml":  cmd.FormatYaml,
		"json":  cmd.FormatJson,
		"smart": cmd.FormatSmart,
		"tab":   c.formatTab,
	})

	f.StringVar(&c.detail, "d", "", "include user details, comma separated list of external_id, email, gravatar_id, or fullname output is forced to tab separated")
	f.StringVar(&c.email, "e", "", "email address of the user")
	f.StringVar(&c.email, "email", "", "")
	f.UintVar(&c.lastLoginDays, "last-login", 0, "users whose last successful login was within this number of days")
	f.UintVar(&c.lastDischargeDays, "last-discharge", 0, "users whose last successful discharge was within this number of days")
}

func (c *findCommand) Init(args []string) error {
	return errgo.Mask(c.candidCommand.Init(nil))
}

func (c *findCommand) Run(ctxt *cmd.Context) error {
	defer c.Close(ctxt)
	client, err := c.candidCommand.Client(ctxt)
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
	if "" == c.detail {
		return c.out.Write(ctxt, usernames)
	}
	fields := strings.Split(c.detail, ",")
	var user_output []map[string]string
	for _, u := range usernames {
		user_out := make(map[string]string)
		user_out["username"] = u
		user, err2 := client.User(context.Background(), &params.UserRequest{
			Username: params.Username(u),
		})
		if err2 != nil {
			fmt.Fprintf(ctxt.Stderr, "%v ... continuing\n", err2)
		}
		for _, f := range fields {
			switch strings.ToLower(strings.Trim(f, " ")) {
			case "email":
				user_out["email"] = user.Email
			case "external_id":
				user_out["external_id"] = user.ExternalID
			case "fullname":
				user_out["fullname"] = user.FullName
			case "gravatar_id":
				user_out["gravatar_id"] = user.GravatarID
			}
		}
		user_output = append(user_output, user_out)
	}
	return c.out.Write(ctxt, user_output)
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

func (c *findCommand) formatTab(writer io.Writer, value interface{}) error {
	users, ok := value.([]map[string]string)
	if ok {
		return c.formatTabMap(writer, users)
	}
	userl, ok := value.([]string)
	if ok {
		return c.formatTabSlice(writer, userl)
	}
	return nil
}

func (c *findCommand) formatTabMap(writer io.Writer, users []map[string]string) error {
	fields := []string{"username"}
	for _, f := range strings.Split(c.detail, ",") {
		fields = append(fields, f)
	}
	i := 0
	s := len(fields)
	for _, k := range fields {
		io.WriteString(writer, k)
		if i < s {
			io.WriteString(writer, "\t")
		}
		i++
	}
	io.WriteString(writer, "\n")
	ul := len(users)
	for j, u := range users {
		i = 0
		s = len(users[0])
		for _, k := range fields {
			if u[k] == "" {
				u[k] = "-"
			}
			io.WriteString(writer, u[k])
			if i < s {
				io.WriteString(writer, "\t")
			}
			i++
		}
		if j < ul {
			io.WriteString(writer, "\n")
		}
	}
	return nil
}

func (c *findCommand) formatTabSlice(writer io.Writer, users []string) error {
	for _, u := range users {
		io.WriteString(writer, u)
	}
	return nil
}
