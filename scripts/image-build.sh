
#!/bin/bash

# This script builds the candid docker image and pushes it to the
# configured docker registry,
# Required environment variables:
# - DOCKER_REGISTRY
# - GIT_VERSION (optional)
# - http_proxy
# - https_proxy
# - no_proxy

set -ex

# If there is a GIT_VERSION set, use that instead of master
if [ -n "${GIT_VERSION}" ]; then
  git checkout $GIT_VERSION
fi

VERSION=`git describe --dirty --always`
GIT_COMMIT=`git rev-parse --verify HEAD`

docker build \
       --build-arg http_proxy \
       --build-arg https_proxy \
       --build-arg no_proxy \
       --build-arg NO_PROXY \
       -t ${DOCKER_REGISTRY}/candid:${VERSION} \
       -f ./Dockerfile .
docker tag ${DOCKER_REGISTRY}/candid:${VERSION} ${DOCKER_REGISTRY}/candid:latest
docker push ${DOCKER_REGISTRY}/candid:${VERSION}
docker push ${DOCKER_REGISTRY}/candid:latest
