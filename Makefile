# Copyright 2014 Canonical Ltd.
# Licensed under the AGPLv3, see LICENCE file for details.
# Makefile for the candid identity service.

GIT_COMMIT := $(shell git rev-parse --verify HEAD)
GIT_VERSION := $(shell git describe --dirty)
ARCH := $(shell dpkg --print-architecture)

DEPENDENCIES := build-essential bzr
SNAP_DEPENDENCIES := go snapcraft

default: build

build: version/init.go
	go build ./...

check: version/init.go
	go test ./...

install: version/init.go
	go install $(INSTALL_FLAGS) -v ./...

clean:
	go clean ./...
	-$(RM) version/init.go
	-snapcraft clean

# Reformat source files.
format:
	gofmt -w -l .

# Reformat and simplify source files.
simplify:
	gofmt -w -l -s .

candidsrv: version/init.go
	go build ./cmd/candidsrv

# Run the candid server.
server: candidsrv
	./candidsrv cmd/candidsrv/config.yaml

# Generate version information
version/init.go: version/init.go.tmpl FORCE
	gofmt -r "unknownVersion -> Version{GitCommit: \"${GIT_COMMIT}\", Version: \"${GIT_VERSION}\",}" $< >$@

# Generate snaps
candid_$(GIT_VERSION)_$(ARCH).snap:
	snapcraft

RELEASE_BINARY_PACKAGES=./cmd/candidsrv

.PHONY: deploy
deploy: candid_$(GIT_VERSION)_$(ARCH).snap
	$(MAKE) -C charm build
	juju deploy -v ./charm/build/candid --resource candid=candid_$(GIT_VERSION)_$(ARCH).snap

# Install packages required to develop the candid service and run tests.
APT_BASED := $(shell command -v apt-get >/dev/null; echo $$?)
sysdeps:
ifeq ($(APT_BASED),0)
	@echo Installing dependencies
	@sudo apt-get update
	@sudo apt-get -y install $(DEPENDENCIES) 
	@sudo snap install $(SNAP_DEPENDENCIES)
else
	@echo sysdeps runs only on systems with apt-get
	@echo on OS X with homebrew try: brew install bazaar mongodb
endif

image:
	DOCKER_BUILDKIT=1 \
	docker build \
		--cache-from candid:latest \
		. -f ./Dockerfile -t candid

help:
	@echo -e 'Identity service - list of make targets:\n'
	@echo 'make - Build the package.'
	@echo 'make check - Run tests.'
	@echo 'make install - Install the package.'
	@echo 'make server - Start the candid server.'
	@echo 'make clean - Remove object files from package source directories.'
	@echo 'make sysdeps - Install the development environment system packages.'
	@echo 'make format - Format the source files.'
	@echo 'make simplify - Format and simplify the source files.'

.PHONY: build check install clean format server simplify snap sysdeps help FORCE

FORCE:
