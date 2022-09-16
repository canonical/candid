#!/bin/sh
#
# set-version.sh
# Set the version built into the application.

set -e

if [ -z "${GIT_COMMIT}" ]; then
	exit 0
fi

if [ -z "${VERSION}" ]; then
	exit 0
fi

gofmt -r "unknownVersion -> Version{GitCommit: \"${GIT_COMMIT}\", Version: \"${VERSION}\",}" version/init.go.tmpl > version/init.go
