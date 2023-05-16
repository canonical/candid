# syntax=docker/dockerfile:1.3.1
FROM ubuntu:20.04 AS build
SHELL ["/bin/bash", "-c"]
ENV GVM_VERSION=master
COPY ./go.mod ./go.mod
RUN apt-get update && \
    apt-get -y install gcc bison binutils make git gcc curl build-essential mercurial ca-certificates
RUN bash < <(curl -SL -v https://raw.githubusercontent.com/moovweb/gvm/${GVM_VERSION}/binscripts/gvm-installer) && \
    source /root/.gvm/scripts/gvm && \
    gvm install go$(cat go.mod | sed -n "/^go/p" | cut -d ' ' -f 2)  -B && \
    gvm use go$(cat go.mod | sed -n "/^go/p" | cut -d ' ' -f 2)  --default

FROM build as build-env
ARG GIT_COMMIT
ARG VERSION
WORKDIR /usr/src/candid
SHELL ["/bin/bash", "-c"]
COPY . .
RUN --mount=type=ssh source /root/.gvm/scripts/gvm && ./scripts/set-version.sh
RUN --mount=type=ssh source /root/.gvm/scripts/gvm && go mod vendor
RUN --mount=type=ssh source /root/.gvm/scripts/gvm && GOBIN=/usr/src/candid go install gopkg.in/macaroon-bakery.v2/cmd/bakery-keygen@latest
RUN --mount=type=ssh source /root/.gvm/scripts/gvm && go build -o candidsrv -race -v -a -mod vendor ./cmd/candidsrv
RUN --mount=type=ssh source /root/.gvm/scripts/gvm && go build -o candid -race -v -a -mod vendor ./cmd/candid

# Define a smaller single process image for deployment
FROM ubuntu:20.04 AS deploy-env
RUN apt-get -qq update && apt-get -qq install -y ca-certificates
WORKDIR /root/
RUN mkdir www
RUN mkdir logs
COPY --from=build-env /usr/src/candid/candidsrv .
COPY --from=build-env /usr/src/candid/candid .
COPY --from=build-env /usr/src/candid/bakery-keygen .
COPY --from=build-env /usr/src/candid/static ./www/static/
COPY --from=build-env /usr/src/candid/templates ./www/templates
RUN touch config.yaml
ENTRYPOINT ["./candidsrv"]
CMD ["config.yaml"]
