# Copyright 2014 Canonical Ltd.
# Makefile for the identity service.

ifndef GOPATH
$(warning You need to set up a GOPATH.)
endif

PROJECT := github.com/CanonicalLtd/blues-identity
PROJECT_DIR := $(shell go list -e -f '{{.Dir}}' $(PROJECT))

GIT_COMMIT := $(shell git rev-parse --verify HEAD)
GIT_VERSION := $(shell git describe --dirty)

ifeq ($(shell uname -p | sed -r 's/.*(x86|armel|armhf).*/golang/'), golang)
	GO_C := golang
	INSTALL_FLAGS :=
else
	GO_C := gccgo-4.9 gccgo-go
	INSTALL_FLAGS := -gccgoflags=-static-libgo
endif

define DEPENDENCIES
  build-essential
  bzr
  juju-mongodb
  mongodb-server
  $(GO_C)
endef

default: build

$(GOPATH)/bin/godeps:
	go get -v launchpad.net/godeps

# Start of GOPATH-dependent targets. Some targets only make sense -
# and will only work - when this tree is found on the GOPATH.
ifeq ($(CURDIR),$(PROJECT_DIR))

build: version/init.go
	go build $(PROJECT)/...

check: version/init.go
	go test $(PROJECT)/...

release: identity-$(GIT_VERSION).tar.xz

install: version/init.go
	go install $(INSTALL_FLAGS) -v $(PROJECT)/...

clean:
	$(MAKE) -C snap/idm clean
	$(MAKE) -C snap/user-admin clean
	go clean $(PROJECT)/...
	-$(RM) version/init.go

else

build:
	$(error Cannot $@; $(CURDIR) is not on GOPATH)

check:
	$(error Cannot $@; $(CURDIR) is not on GOPATH)

install:
	$(error Cannot $@; $(CURDIR) is not on GOPATH)

release:
	$(error Cannot $@; $(CURDIR) is not on GOPATH)

clean:
	$(error Cannot $@; $(CURDIR) is not on GOPATH)

endif
# End of GOPATH-dependent targets.

# Reformat source files.
format:
	gofmt -w -l .

# Reformat and simplify source files.
simplify:
	gofmt -w -l -s .

# Run the identity server.
server: install
	idserver -logging-config INFO cmd/idserver/config.yaml

# Update the project Go dependencies to the required revision.
deps: $(GOPATH)/bin/godeps
	$(GOPATH)/bin/godeps -u dependencies.tsv

# Generate the dependencies file.
create-deps: $(GOPATH)/bin/godeps
	godeps -t $(shell go list $(PROJECT)/...) > dependencies.tsv || true

# Generate version information
version/init.go: version/init.go.tmpl FORCE
	gofmt -r "unknownVersion -> Version{GitCommit: \"${GIT_COMMIT}\", Version: \"${GIT_VERSION}\",}" $< > $@

# Generate snaps
snap:
	$(MAKE) -C snap/idm
	$(MAKE) -C snap/user-admin

# Build a release tarball
identity-$(GIT_VERSION).tar.xz: version/init.go
	mkdir -p identity-$(GIT_VERSION)/bin
	GOBIN=$(CURDIR)/identity-$(GIT_VERSION)/bin go install $(INSTALL_FLAGS) -v $(PROJECT)/...
	mv identity-$(GIT_VERSION)/bin/idserver identity-$(GIT_VERSION)/bin/identity
	cp -r $(CURDIR)/templates identity-$(GIT_VERSION)
	cp -r $(CURDIR)/static identity-$(GIT_VERSION)
	tar cv identity-$(GIT_VERSION) | xz > $@
	-rm -r identity-$(GIT_VERSION)


# Install packages required to develop the identity service and run tests.
APT_BASED := $(shell command -v apt-get >/dev/null; echo $$?)
sysdeps:
ifeq ($(APT_BASED),0)
ifeq ($(shell lsb_release -cs|sed -r 's/precise|quantal|raring/old/'),old)
	@echo Adding PPAs for golang and mongodb
	@sudo apt-add-repository --yes ppa:juju/golang
	@sudo apt-add-repository --yes ppa:juju/stable
endif
	@echo Installing dependencies
	sudo apt-get update
	@sudo apt-get -y install $(strip $(DEPENDENCIES)) \
	$(shell apt-cache madison juju-mongodb mongodb-server snapcraft | head -1 | cut -d '|' -f1)
else
	@echo sysdeps runs only on systems with apt-get
	@echo on OS X with homebrew try: brew install bazaar mongodb
endif

help:
	@echo -e 'Identity service - list of make targets:\n'
	@echo 'make - Build the package.'
	@echo 'make check - Run tests.'
	@echo 'make install - Install the package.'
	@echo 'make release - Build a binary tarball of the package.'
	@echo 'make server - Start the identity server.'
	@echo 'make clean - Remove object files from package source directories.'
	@echo 'make sysdeps - Install the development environment system packages.'
	@echo 'make deps - Set up the project Go dependencies.'
	@echo 'make create-deps - Generate the Go dependencies file.'
	@echo 'make format - Format the source files.'
	@echo 'make simplify - Format and simplify the source files.'

.PHONY: build check install clean format release server simplify snap sysdeps help FORCE

FORCE:
