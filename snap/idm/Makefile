# Copyright 2016 Canonical Ltd.
# Makefile for the idm snap.

PACKAGE := idm
GIT_VERSION := $(shell git describe --dirty)

snap: $(PACKAGE)_$(GIT_VERSION)_amd64.snap

$(PACKAGE)_$(GIT_VERSION)_amd64.snap: snapcraft.yaml
	snapcraft

snapcraft.yaml: snapcraft.yaml.in FORCE
	sed -e "s/IDM_VERSION/$(GIT_VERSION)/" < snapcraft.yaml.in > snapcraft.yaml

clean: snapcraft.yaml
	snapcraft clean
	-rm snapcraft.yaml

.PHONY: snap clean FORCE

FORCE:
