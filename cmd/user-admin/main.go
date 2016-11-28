// Copyright 2016 Canonical Ltd.
package main

import (
	"os"

	"github.com/juju/cmd"

	"github.com/CanonicalLtd/blues-identity/cmd/user-admin/internal/admincmd"
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
