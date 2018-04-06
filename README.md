# Identity service

The identity service provides the ability to manage, create, remove and change
Juju users and Juju environments. It is designed as a proxy to the external 
identity providers.

## Installation

To start using the candid service, first ensure you have a valid Go environment,
then run the following:

    go get github.com/CanonicalLtd/candid
    cd $GOPATH/github.com/CanonicalLtd/candid

## Go dependencies

The project uses godeps (https://launchpad.net/godeps) to manage Go
dependencies. To install this, run:

    go get launchpad.net/godeps

After installing it, you can update the dependencies
to the revision specified in the `dependencies.tsv` file with the following:

    make deps

Use `make create-deps` to update the dependencies file.

## Development environment

A couple of system packages are required in order to set up a development
environment. To install them, run the following:

    make sysdeps

At this point, from the root of this branch, run the command::

    make install

The command above builds and installs the identity service binaries, and places
them in `$GOPATH/bin`. This is the list of the installed commands:

- candidsrv: start the Candid identity server;

## Candid server

The server can be started with the following command:

    candidsrv -logging-config INFO cmd/candidsrv/config.yaml

The same result can be achieved more easily by running `make server`.
Note that this configuration *should not* be used when running a production
server.

At this point the server starts listening on port 8081 (as specified in the
config YAML file).

## Testing

Run `make check` to test the application.
Run `make help` to display help about all the available make targets.
