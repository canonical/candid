ARG DOCKER_REGISTRY
FROM ${DOCKER_REGISTRY}golang:1.17 AS golang
RUN go version

FROM ${DOCKER_REGISTRY}ubuntu:20.04 AS build-env

ARG http_proxy
ARG https_proxy
ARG no_proxy
ARG NO_PROXY

# Install general deps
RUN apt-get -qq update && apt-get -qq install -y ca-certificates curl git gcc build-essential 

# Set-up go
COPY --from=golang /usr/local/go/ /usr/local/go/
ENV PATH /usr/local/go/bin:$PATH
ENV GO111MODULE=on

RUN mkdir /src
WORKDIR /src

ARG GH_SSH_KEY
ARG GH_USERNAME
ARG GH_PASSWORD
ARG GOPROXY
ARG GOSUMDB
ARG GOPRIVATE=github.com/CanonicalLtd
COPY ./scripts/docker-github-auth.sh .
RUN ./docker-github-auth.sh

ARG GOMODMODE=readonly
# Cache modules needed in a docker layer to speed up subsequent builds
COPY go.mod .
COPY go.sum .
RUN [ "$GOMODMODE" = "vendor" ] || go mod download

COPY . .
# Set version
ARG GIT_COMMIT
ARG VERSION
RUN ./scripts/set-version.sh

ARG TAGS
RUN GOBIN=/src go install gopkg.in/macaroon-bakery.v2/cmd/bakery-keygen@latest
RUN go build --tags "$TAGS" -mod $GOMODMODE -o candidsrv ./cmd/candidsrv
RUN go build --tags "$TAGS" -mod $GOMODMODE -o candid ./cmd/candid


# Define a smaller single process image for deployment
FROM ${DOCKER_REGISTRY}ubuntu:20.04 AS deploy-env
RUN apt-get -qq update && apt-get -qq install -y ca-certificates
WORKDIR /root/
RUN mkdir www
RUN mkdir logs
COPY --from=build-env /src/candidsrv .
COPY --from=build-env /src/candid .
COPY --from=build-env /src/bakery-keygen .
COPY --from=build-env /src/static ./www/static/
COPY --from=build-env /src/templates ./www/templates
RUN touch config.yaml
CMD ["./candidsrv config.yaml"]

