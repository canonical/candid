# syntax=docker/dockerfile:1.3.1
FROM ubuntu:20.04 as build-env
ARG GIT_COMMIT
ARG VERSION
ARG GO_VERSION
WORKDIR /usr/src/candid
SHELL ["/bin/bash", "-c"]
RUN apt update && apt install wget git -y
RUN wget -L "https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz"
RUN tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
ENV PATH="${PATH}:/usr/local/go/bin"
COPY . .
RUN go build -o candidsrv -v ./cmd/candidsrv
RUN go build -o candid -v ./cmd/candid
RUN GOBIN=/usr/src/candid go install gopkg.in/macaroon-bakery.v2/cmd/bakery-keygen@latest

# Define a smaller single process image for deployment
FROM ubuntu:20.04 AS deploy-env
RUN apt-get -qq update && apt-get -qq install -y ca-certificates curl
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
