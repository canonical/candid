// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.
package main

import (
	"os"

	"github.com/juju/cmd"

	"gopkg.in/canonical/candid.v2/cmd/candid/internal/admincmd"
)

func main() {
	ctxt := &cmd.Context{
		Dir:    ".",
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Stdin:  os.Stdin,
	}
	os.Exit(cmd.Main(admincmd.New(), ctxt, os.Args[1:]))
}
