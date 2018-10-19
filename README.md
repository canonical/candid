# Candid Identity service

The Candid server provides a macaroon-based authentication service.

## Installation

The easiest way to start using the candid service is with the snap:

    snap install candid --edge

The configuration file used by the snap can be found in
`/var/snap/candid/common/config.yaml`.

## Development

### Requirements

Candid requires go1.11 or later to build. This is available in the go snap:

    snap install go

Go will additionally require installing the following packages in order
that it can fetch and build candid dependencies:

    apt install build-essential bzr git

### Source

Get the source from `github.com/CanoniclaLtd/candid`.

    git clone git@github.com:CanonicalLtd/candid

It is recommended that you check out the source outside of any `$GOPATH`
(`$HOME/go` by default). If you do wish to check out into a `$GOPATH`
then you will need to set the environment variable `GO111MODULE=on`.

### Testing

The store/mgostore component additionally requires mongodb to be
installed, this should be installed from the system packages:

    apt install mongodb

The store/sqlstore component additionally requires a running
postgresql, this may be running on a different system. The posgresql
system to use is specified using the standard postgresql [environment
variables](https://www.postgresql.org/docs/10/static/libpq-envars.html).
To skip running postgresql tests set the environment variable
`PGTESTDISABLE=1`.

Tests are run by running make check in the root of the source tree. The
tests for a single package can be run by running `go test` in the
package directory.
