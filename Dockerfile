ARG BASEIMAGE=golang:1.19
ARG RUNIMAGE=alpine:3.14

FROM $BASEIMAGE AS build

ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0

RUN apt update && apt install -y llvm clang

WORKDIR /work
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY api api
COPY cmd cmd
COPY crds crds
COPY deploy deploy
COPY pkg pkg
COPY main.go main.go
COPY Makefile Makefile

RUN --mount=type=cache,target=/root/.cache/go-build,sharing=private \
  make build

FROM $RUNIMAGE as run

RUN apk --no-cache add curl
COPY --from=build /work/bin/skouter /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/skouter"]
